use os_pipe;
use std::process::Command;
use std::io::{BufReader, BufRead, Write};

fn sign() -> Option<Vec<String>> {
    // to_gpg_stdin -> gpg_stdin
    let (gpg_stdin, mut to_gpg_stdin) = os_pipe::pipe().unwrap();
    // from_gpg_stdout  <- gpg_stdout
    let (from_gpg_stdout, gpg_stdout) = os_pipe::pipe().unwrap();
    // from_gpg_stderr <- gpg_stderr
    let (gpg_stderr, mut to_gpg_stderr) = os_pipe::pipe().unwrap();

    let mut responses = BufReader::new(from_gpg_stdout);

    let mut gpg_server = Command::new("gpgsm");
    gpg_server.arg("--server")
        .stdin(gpg_stdin)
        .stdout(gpg_stdout)
        .stderr(gpg_stderr);
    let mut handle = gpg_server.spawn().unwrap();
    drop(gpg_server);

    let mut line = String::new();

    // get the OK welcome message
    responses.read_line(&mut line).unwrap();
    if !line.starts_with("OK") {
        print!("ERROR: {}", line);
        return None;
    }
    print!("< {}", line);
    line.clear();

    // send INPUT command
    println!("> INPUT FD=2");
    write!(to_gpg_stdin, "INPUT FD=2\n").unwrap();
    // get the OK welcome message
    responses.read_line(&mut line).unwrap();
    if !line.starts_with("OK") {
        print!("ERROR: {}", line);
        return None;
    }
    print!("< {}", line);
    line.clear();

    // send OUTPUT command
    println!("> OUTPUT FD=1 --armor");
    write!(to_gpg_stdin, "OUTPUT FD=1 --armor\n").unwrap();
    // get the OK welcome message
    responses.read_line(&mut line).unwrap();
    if !line.starts_with("OK") {
        print!("ERROR: {}", line);
        return None;
    }
    print!("< {}", line);
    line.clear();

    // send SIGN command
    println!("> SIGN --detached");
    write!(to_gpg_stdin, "SIGN --detached\n").unwrap();

    // write the data to GPG's stderr
    println!("2> Hello");
    write!(to_gpg_stderr, "Hello").unwrap();
    to_gpg_stderr.flush().unwrap();

    // hang up our end so that GPG knows to read the data
    drop(to_gpg_stderr);

    // read the signature back from GPG
    let mut sig = Vec::new();
    loop {
        line.clear();
        responses.read_line(&mut line).unwrap();
        if line.starts_with("S") {
            print!("< STATUS: {}", line);
        } else if line.starts_with("OK") {
            print!("< {}", line);
            break;
        } else {
            //print!("{}", line);
            sig.push(line.clone());
        }
    }
    line.clear();

    // send BYE command
    println!("> BYE");
    write!(to_gpg_stdin, "BYE\n").unwrap();
    
    // get the OK welcome message
    responses.read_line(&mut line).unwrap();
    if !line.starts_with("OK") {
        print!("ERROR: {}", line);
        return None;
    }
    print!("< {}", line);
    line.clear();

    handle.wait().unwrap();

    Some(sig)
}

fn verify(sig: &Vec<String>) -> Option<Vec<String>> {
    // to_gpg_stdin -> gpg_stdin
    let (gpg_stdin, mut to_gpg_stdin) = os_pipe::pipe().unwrap();
    // from_gpg_stdout  <- gpg_stdout
    let (from_gpg_stdout, gpg_stdout) = os_pipe::pipe().unwrap();
    // from_gpg_stderr <- gpg_stderr
    let (gpg_stderr, mut to_gpg_stderr) = os_pipe::pipe().unwrap();

    let mut responses = BufReader::new(from_gpg_stdout);

    println!("running gpgsm for verify");
    let mut gpg_server = Command::new("gpgsm");
    gpg_server.arg("--server")
        .stdin(gpg_stdin)
        .stdout(gpg_stdout)
        .stderr(gpg_stderr);
    let mut handle = gpg_server.spawn().unwrap();
    drop(gpg_server);

    let mut line = String::new();

    // get the OK welcome message
    responses.read_line(&mut line).unwrap();
    if !line.starts_with("OK") {
        print!("ERROR: {}", line);
        return None;
    }
    print!("< {}", line);
    line.clear();

    // send INPUT command
    println!("> INPUT FD=2 --armor");
    write!(to_gpg_stdin, "INPUT FD=2 --armor\n").unwrap();
    // get the OK welcome message
    responses.read_line(&mut line).unwrap();
    if !line.starts_with("OK") {
        print!("ERROR: {}", line);
        return None;
    }
    print!("< {}", line);
    line.clear();

    // send VERIFY command
    println!("> VERIFY");
    write!(to_gpg_stdin, "VERIFY\n").unwrap();

    // write the data to GPG's stdin
    println!("> Hello to stdin");
    write!(to_gpg_stdin, "Hello").unwrap();
    to_gpg_stdin.flush().unwrap();
    //drop(to_gpg_stdin);

    // write the sig to GPG's stderr
    for l in sig {
        print!("2> {}", l);
        write!(to_gpg_stderr, "{}", l).unwrap();
    }
    to_gpg_stderr.flush().unwrap();
    drop(to_gpg_stderr);

    // read the results back
    let mut res = Vec::new();
    loop {
        line.clear();
        responses.read_line(&mut line).unwrap();
        if line.starts_with("S") {
            print!("< STATUS: {}", line);
        } else if line.starts_with("OK") {
            print!("< {}", line);
            break;
        } else {
            res.push(line.clone());
        }
    }
    line.clear();

    // send BYE command
    println!("> BYE");
    write!(to_gpg_stdin, "BYE\n").unwrap();
    
    // get the OK welcome message
    responses.read_line(&mut line).unwrap();
    if !line.starts_with("OK") {
        print!("ERROR: {}", line);
        return None;
    }
    print!("< {}", line);
    line.clear();

    handle.wait().unwrap();

    Some(res)
}

fn main() {
    let sig = match sign() {
        Some(s) => s,
        None => Vec::new()
    };
    for l in &sig {
        print!("{}", l);
    }
    let _ = verify(&sig);
}
