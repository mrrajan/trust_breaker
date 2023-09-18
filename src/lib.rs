use std::process::Command;

pub fn run_command(command: &str, args: &[&str]) -> Vec<u8> {
    let output = Command::new(&command)
        .args(args)
        .output().expect("Failed to execute the script");
    output.stdout
}

pub fn string_slicer(input:String, start:&str, end: &str, exclude: bool)-> String{
    let start_pos = input.find(start).expect("Start position not found");
    let end_pos = input.find(end).expect("End position not found");
    if exclude{
        let before = &input[..start_pos];
        let after = &input[end_pos + end.len()..]; 
        before.to_string()+after
    }else{
        input[start_pos..end_pos+end.len()].to_string()
    }
}