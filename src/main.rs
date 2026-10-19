use std::process::ExitCode;

use ntfs_suite::app;

#[tokio::main]
async fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    if args.len() >= 2 && args[1] == "parse" {
        return cli_parse(&args);
    }
    match app::run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("server error: {}", e);
            ExitCode::from(1)
        }
    }
}

fn cli_parse(args: &[String]) -> ExitCode {
    use std::fs::File;
    use std::io::BufReader;
    use ntfs_suite::mft::path_resolver::PathResolver;
    use ntfs_suite::mft::stream::{detect_record_size_reader, for_each_record};

    if args.len() < 3 {
        eprintln!("usage: ntfssuite parse <path-to-$MFT>");
        return ExitCode::from(2);
    }
    let file = match File::open(&args[2]) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("cannot open {}: {}", args[2], e);
            return ExitCode::from(1);
        }
    };
    let mut reader = BufReader::with_capacity(1 << 20, file);
    let record_size = detect_record_size_reader(&mut reader).unwrap_or(1024);
    let mut resolver = PathResolver::new();
    let mut count: u64 = 0;
    let result = for_each_record(&mut reader, record_size, |number, record| {
        resolver.insert_summary(PathResolver::summarize(number, record));
        count += 1;
        true
    });
    match result {
        Ok(stats) => {
            println!("parsed {}", count);
            println!("baad {}", stats.baad);
            println!("errors {}", stats.errors);
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("parse failed: {}", e);
            ExitCode::from(1)
        }
    }
}
