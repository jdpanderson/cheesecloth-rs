//! Small files written atomically: a new file is written and synced, then
//! renamed over the old one.

use std::{
    fs::{self, File},
    io::{self, Write},
    path::{Path, PathBuf},
};

use serde::{Serialize, de::DeserializeOwned};

use crate::{Acceptor, Chosen, InvalidRequest, Reply, Request};

/// Writes `value` to `path`, so that a crash leaves either the old or the new
/// contents.
pub fn save<T: Serialize>(path: &Path, value: &T) -> io::Result<()> {
    let bytes = postcard::to_stdvec(value).map_err(io::Error::other)?;
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp = PathBuf::from(tmp);
    let mut file = File::create(&tmp)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    fs::rename(&tmp, path)?;
    // The rename is only durable once the directory is synced.
    let dir = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    File::open(dir)?.sync_all()
}

/// Reads a value written by [`save`], or `None` if there is no file.
pub fn load<T: DeserializeOwned>(path: &Path) -> io::Result<Option<T>> {
    match fs::read(path) {
        Ok(bytes) => postcard::from_bytes(&bytes)
            .map(Some)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

/// An acceptor whose state is saved to a file before each reply.
pub struct Stored<N, V, P = ()> {
    acceptor: Acceptor<N, V, P>,
    path: PathBuf,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Invalid(#[from] InvalidRequest),
    #[error("can't save the acceptor state: {0}")]
    Io(#[from] io::Error),
}

impl<N, V, P> Stored<N, V, P>
where
    N: Clone + Ord + Serialize + DeserializeOwned,
    V: Clone + PartialEq + Serialize + DeserializeOwned,
    P: Clone + Serialize + DeserializeOwned,
{
    /// Opens the acceptor state in `path`, or starts empty if there is none.
    pub fn open(path: PathBuf) -> io::Result<Self> {
        let acceptor = load(&path)?.unwrap_or_default();
        Ok(Stored { acceptor, path })
    }

    /// Saves `acceptor` as the state in `path`, in place of any there.
    pub fn create(path: PathBuf, acceptor: Acceptor<N, V, P>) -> io::Result<Self> {
        save(&path, &acceptor)?;
        Ok(Stored { acceptor, path })
    }

    pub fn acceptor(&self) -> &Acceptor<N, V, P> {
        &self.acceptor
    }

    /// Answers a request, once the new state is on disk. If saving fails,
    /// the state is left as it was.
    pub fn handle(&mut self, req: Request<N, V>) -> Result<Reply<N, V>, Error> {
        self.update(|next| Ok(next.handle(req)?))
    }

    pub fn endorse(
        &mut self,
        ballot: crate::Ballot<N>,
        value: crate::Agreed<N, V>,
    ) -> Result<(), Error> {
        self.update(|next| {
            next.endorse(ballot, value)?;
            Ok(((), true))
        })
    }

    pub fn handle_proven(&mut self, req: Request<N, V>, proof: P) -> Result<Reply<N, V>, Error> {
        self.update(|next| Ok(next.handle_proven(req, proof)?))
    }

    /// Records an agreed value (see [`Acceptor::learn`]). If saving fails,
    /// the state is left as it was.
    pub fn learn(&mut self, chosen: Chosen<N, V>, proof: P) -> io::Result<()> {
        self.update(|next| Ok(((), next.learn(chosen, proof))))
    }

    /// Every mutation uses the same save-before-publish boundary. Changes
    /// become visible in memory only after their save succeeds.
    fn update<R, E: From<io::Error>>(
        &mut self,
        change: impl FnOnce(&mut Acceptor<N, V, P>) -> Result<(R, bool), E>,
    ) -> Result<R, E> {
        let mut next = self.acceptor.clone();
        let (result, changed) = change(&mut next)?;
        if changed {
            save(&self.path, &next)?;
            self.acceptor = next;
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests;
