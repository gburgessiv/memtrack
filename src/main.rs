use std::fs;
use std::io;
use std::collections::HashMap;

type FailureOr<T> = Result<T, failure::Error>;

async fn enumerate_children_of(my_pid: u32) -> FailureOr<Vec<u32>> {
    macro_rules! try_continue {
        ($x:expr) => {{
            match $x {
                Ok(x) => x,
                Err(x) => {
                    if x.kind() == io::ErrorKind::NotFound {
                        continue;
                    }
                    return Err(x.into());
                },
            }
        }}
    }

    // I have ~1K procs on my machine rn.
    let mut ps_map: HashMap<u32, u32> = HashMap::with_capacity(2048);
    for file in fs::read_dir("/tmp")? {
        let file = try_continue!(file);
        let pid = match file.file_name().to_str().and_then(|x| x.parse::<u32>().ok()) {
            None => continue,
            Some(y )=> y,
        };
    }

    unimplemented!();
}

// async fn poll_subprocess_memory_usage(



fn main() -> FailureOr<()> {
    let matches = clap::App::new("memtrack")
        .arg(
            clap::Arg::with_name("log_file")
                .long("log_file")
                .takes_value(true)
                .default_value("/tmp/memory.log")
                .help("File to write the memory log to."),
        )
        .arg(
            clap::Arg::with_name("log_period")
                .long("log_period")
                .takes_value(true)
                .default_value("0.5")
                .help("Period at which to log in seconds.")
                .validator(|s| -> Result<(), String> {
                    let n: f64 = s
                        .parse()
                        .map_err(|_| "Need a valid floating-point number")?;
                    if n <= 0. {
                        Err("Need a non-negative floating-point number".into())
                    } else {
                        Ok(())
                    }
                }),
        )
        .arg(
            clap::Arg::with_name("tcmalloc_profile_prefix")
                .long("tcmalloc_profile_prefix")
                .takes_value(true)
                .help(concat!(
                    "Turns on tcmalloc profiling, and causes it to dump profiles to the given ",
                    "prefix; enables tcmalloc by default"
                )),
        )
        .arg(
            clap::Arg::with_name("tcmalloc_heap_check")
                .long("tcmalloc_heap_check")
                .help("Turns on tcmalloc heap checking; enables tcmalloc by default"),
        )
        .arg(
            clap::Arg::with_name("use_tcmalloc")
                .long("use_tcmalloc")
                .help("Turns on tcmalloc"),
        )
        .arg(
            clap::Arg::with_name("command")
                .takes_value(true)
                .required(true)
                .multiple(true),
        )
        .get_matches();

    let log_file = matches.value_of("log_file").unwrap();
    let log_period: f64 = matches
        .value_of("log_period")
        .and_then(|x| x.parse().ok())
        .unwrap();
    let command: Vec<&str> = matches.values_of("command").unwrap().collect();

    let mut subprocess = tokio::process::Command::new(command[0]);
    subprocess.args(&command[1..]);

    let mut tcmalloc_enabled = matches.is_present("use_tcmalloc");
    if let Some(tcmalloc_prefix) = matches.value_of("tcmalloc_profile_prefix") {
        tcmalloc_enabled = true;

        fs::create_dir_all(&tcmalloc_prefix)?;
        subprocess.env("HEAPPROFILE", tcmalloc_prefix);
    }

    if matches.is_present("tcmalloc_heap_check") {
        tcmalloc_enabled = true;
        subprocess.env("HEAPCHECK", "normal");
    }

    if tcmalloc_enabled {
        subprocess.env("LD_PRELOAD", "/usr/lib/x86_64-linux-gnu/libtcmalloc.so.4");
    }


}
