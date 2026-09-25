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
mod tests {
    use super::*;
    use crate::Ballot;

    #[test]
    fn save_and_load() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("x");
        assert_eq!(load::<u32>(&path).unwrap(), None);
        save(&path, &7u32).unwrap();
        save(&path, &8u32).unwrap();
        assert_eq!(load::<u32>(&path).unwrap(), Some(8));
        assert!(!dir.path().join("x.tmp").exists());

        fs::write(&path, [0xff; 20]).unwrap();
        assert_eq!(
            load::<String>(&path).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn stored_acceptor_survives_a_restart() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("acceptor");
        let first = Acceptor::genesis(Chosen::genesis(1, "g".into()), ());
        let mut a = Stored::<u8, String>::create(path.clone(), first).unwrap();
        let prepare = Request::Prepare {
            config: 0,
            ballot: Ballot {
                counter: 3,
                node: 2,
            },
            have: None,
        };
        a.handle(prepare).unwrap();

        let b = Stored::<u8, String>::open(path.clone()).unwrap();
        assert_eq!(a.acceptor(), b.acceptor());
    }

    #[test]
    fn failed_writes_preserve_memory_and_disk_and_can_be_retried() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("acceptor");
        let first = Acceptor::genesis(Chosen::genesis(1, "g".into()), ());
        let mut a = Stored::<u8, String>::create(path.clone(), first).unwrap();
        let before = a.acceptor().clone();
        let ballot = Ballot {
            counter: 3,
            node: 2,
        };
        let mut value = before.learned().unwrap().value.clone();
        value.version += 1;
        value.value = "next".into();
        let chosen = Chosen {
            value: value.clone(),
            ballot: Some(ballot.clone()),
        };
        for operation in 0..4 {
            let mut a = Stored::<u8, String>::create(path.clone(), before.clone()).unwrap();
            let apply = |a: &mut Stored<u8, String>| -> Result<(), Error> {
                match operation {
                    0 => a
                        .handle(Request::Prepare {
                            config: 0,
                            ballot: ballot.clone(),
                            have: None,
                        })
                        .map(drop),
                    1 => a.endorse(ballot.clone(), value.clone()),
                    2 => a
                        .handle_proven(
                            Request::Accept {
                                config: 0,
                                ballot: ballot.clone(),
                                value: value.clone(),
                            },
                            (),
                        )
                        .map(drop),
                    3 => a.learn(chosen.clone(), ()).map_err(Error::from),
                    _ => unreachable!(),
                }
            };
            // The next save can't create its temporary file.
            let tmp = dir.path().join("acceptor.tmp");
            fs::create_dir(&tmp).unwrap();
            assert!(matches!(apply(&mut a), Err(Error::Io(_))));
            assert_eq!(a.acceptor(), &before);
            assert_eq!(
                Stored::<u8, String>::open(path.clone()).unwrap().acceptor(),
                &before
            );

            fs::remove_dir(tmp).unwrap();
            apply(&mut a).unwrap();
            assert_ne!(a.acceptor(), &before);
            assert_eq!(
                Stored::<u8, String>::open(path.clone()).unwrap().acceptor(),
                a.acceptor()
            );
        }

        // Learning an older value doesn't need a write, even with a bad disk.
        a.learn(chosen, ()).unwrap();
        fs::create_dir(dir.path().join("acceptor.tmp")).unwrap();
        a.learn(before.learned().unwrap().clone(), ()).unwrap();
        assert_eq!(a.acceptor().learned().unwrap().state(), "next");
    }
}
