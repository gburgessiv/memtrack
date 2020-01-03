use std::collections::{HashMap, HashSet};
use std::fs;
use std::future::Future;
use std::io;
use std::io::Read;
use std::io::Write;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use failure::bail;

use serde::Serialize;

type FailureOr<T> = Result<T, failure::Error>;

fn enumerate_children_of(main_pid: u32) -> FailureOr<Vec<u32>> {
    macro_rules! try_continue {
        ($x:expr) => {{
            match $x {
                Ok(x) => x,
                Err(x) => {
                    if x.kind() == io::ErrorKind::NotFound {
                        continue;
                    }
                    return Err(x.into());
                }
            }
        }};
    }

    // I have ~1K procs on my machine rn.
    let mut ps_map: HashMap<u32, Vec<u32>> = HashMap::with_capacity(2048);
    let mut proc_file_data = [0u8; 256];
    let mut found_main_pid = false;
    for file in fs::read_dir("/proc")? {
        let file = try_continue!(file);
        let pid = match file
            .file_name()
            .to_str()
            .and_then(|x| x.parse::<u32>().ok())
        {
            None => continue,
            Some(y) => y,
        };

        found_main_pid = found_main_pid || pid == main_pid;

        let mut loc = file.path();
        loc.push("stat");

        let mut stat = try_continue!(fs::File::open(loc));
        let n = stat.read(&mut proc_file_data)?;
        let proc_file_data = &proc_file_data[..n];

        // ${pid} (${name}) ${status} ${ppid} ${pgid} ...
        // Start with the last paren
        let last_paren = match memchr::memrchr(b')', proc_file_data) {
            None => bail!("no end paren found in data for {:?}", file.path()),
            Some(x) => x,
        };

        let ppid: u32 = match proc_file_data[last_paren..]
            .split(|&x| x == b' ')
            .nth(2)
            .and_then(|x| std::str::from_utf8(x).ok())
            .and_then(|x| x.parse::<u32>().ok())
        {
            None => bail!("short read or invalid ppid for {:?}", file.path()),
            Some(x) => x,
        };

        ps_map.entry(ppid).or_default().push(pid);
    }

    if !found_main_pid {
        return Ok(Vec::new());
    }

    let mut result = vec![main_pid];
    let mut i = 0usize;
    while i < result.len() {
        if let Some(children) = ps_map.get(&result[i]) {
            result.extend_from_slice(&children);
        }
        i += 1;
    }
    Ok(result)
}

#[derive(Serialize)]
struct MemInfo {
    anon_bytes: u64,
    shared_bytes: u64,
}

fn read_subprocess_memory_usage(pid: u32) -> Option<MemInfo> {
    let data = fs::read_to_string(format!("/proc/{}/statm", pid)).ok()?;
    // This has a few numbers:
    // - Total program size (VmSize from /proc/${pid}/status)
    // - RSS
    // - Filed-backed pages
    // - Text pages
    // - Unused (always 0)
    // - Data + stack pages
    // - Unused (always 0)
    //
    // ...All measurements are in pages.

    let mut words = data.split_whitespace();
    words.next()?;
    let rss = words.next()?.parse::<u64>().ok()?;
    let shared = words.next()?.parse::<u64>().ok()?;
    let page_size = 4096;
    Some(MemInfo {
        anon_bytes: (rss - shared) * page_size,
        shared_bytes: shared * page_size,
    })
}

#[derive(Serialize)]
struct NewProcess {
    cmdline: Vec<String>,
    pid: u32,
}

#[derive(Serialize)]
#[serde(tag = "type", content = "value")]
enum Record {
    MemInfo(Vec<(u32, MemInfo)>),
    NewProcess(NewProcess),
}

async fn poll_subprocess_memory_usage<F>(
    main_pid: u32,
    period: Duration,
    mut write_record: F,
) -> FailureOr<()>
where
    F: FnMut(Record) -> FailureOr<()>,
{
    let mut last_seen_pids: HashSet<u32> = HashSet::new();

    loop {
        let next_check = Instant::now() + period;
        let pids = enumerate_children_of(main_pid)?;
        if pids.is_empty() {
            return Ok(());
        }

        let mut mem_map: Vec<(u32, MemInfo)> = Vec::with_capacity(pids.len());
        let mut newly_added: Vec<NewProcess> = Vec::new();
        for pid in pids {
            if !last_seen_pids.contains(&pid) {
                let mut cmdline = match fs::read(format!("/proc/{}/cmdline", pid)) {
                    Ok(x) => x,
                    Err(_) => continue,
                };

                while cmdline.last() == Some(&b'\0') {
                    cmdline.pop();
                }

                newly_added.push(NewProcess {
                    cmdline: cmdline
                        .split(|&x| x == b'\0')
                        .map(|x| String::from_utf8_lossy(x).into_owned())
                        .collect(),
                    pid,
                });
            }

            mem_map.push((
                pid,
                match read_subprocess_memory_usage(pid) {
                    None => continue,
                    Some(m) => m,
                },
            ));
        }

        newly_added.sort_by_key(|x| x.pid);
        for proc in newly_added {
            write_record(Record::NewProcess(proc))?;
        }

        last_seen_pids = mem_map.iter().map(|x| x.0).collect();
        mem_map.sort_by_key(|x| x.0);
        write_record(Record::MemInfo(mem_map))?;
        tokio::time::delay_until(next_check.into()).await;
    }
}

struct Select<F1, F2, T>
where
    F1: Future<Output = T>,
    F2: Future<Output = T>,
{
    f1: F1,
    f2: F2,
}

impl<F1, F2, T> Future for Select<F1, F2, T>
where
    F1: Future<Output = T>,
    F2: Future<Output = T>,
{
    type Output = T;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        {
            let inner = unsafe { self.as_mut().map_unchecked_mut(|x| &mut x.f1) };
            match inner.poll(cx) {
                Poll::Ready(x) => return Poll::Ready(x),
                Poll::Pending => (),
            }
        }

        {
            let inner = unsafe { self.map_unchecked_mut(|x| &mut x.f2) };
            match inner.poll(cx) {
                Poll::Ready(x) => return Poll::Ready(x),
                Poll::Pending => (),
            }
        }
        Poll::Pending
    }
}

async fn run_monitored_subproc(
    mut command: tokio::process::Command,
    log_file: String,
    log_period: Duration,
) -> FailureOr<i32> {
    command.kill_on_drop(true);

    let mut log_file = fs::File::create(log_file)?;
    let running = command.spawn()?;
    let pid = running.id();

    let monitor = async move {
        let write_record = move |rec: Record| -> FailureOr<()> {
            serde_json::to_writer(&mut log_file, &rec)?;
            write!(log_file, "\n")?;
            Ok(())
        };
        match poll_subprocess_memory_usage(pid, log_period, write_record).await {
            Err(x) => {
                eprintln!("Error polling subproc memory usage: {}", x);
                1
            }
            Ok(()) => 0,
        }
    };

    let subprocess = async move {
        match running.await {
            Ok(exit_status) => exit_status.code().unwrap_or(127),
            Err(x) => {
                eprintln!("Error waiting on subprocess: {}", x);
                1
            }
        }
    };

    Ok(Select {
        f1: monitor,
        f2: subprocess,
    }
    .await)
}

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
                    if n <= 0.01 {
                        Err("Need a floating-point number >= 0.01".into())
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

    let log_file = matches.value_of("log_file").unwrap().to_string();
    let log_period: Duration = matches
        .value_of("log_period")
        .and_then(|x| x.parse::<f64>().ok())
        .map(|x| Duration::from_millis((x * 1000.) as u64))
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

    let exit_code = tokio::runtime::Runtime::new()?
        .block_on(run_monitored_subproc(subprocess, log_file, log_period))?;
    std::process::exit(exit_code);
}
