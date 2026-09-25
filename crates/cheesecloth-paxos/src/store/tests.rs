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
