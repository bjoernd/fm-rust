extern crate process_memory;
extern crate sysinfo;

/* For reading remote memory */
use process_memory::{Memory, DataMember, Pid, TryIntoProcessHandle};
/* For finding the fm.exe process */
use sysinfo::{ProcessExt, SystemExt};
/* For measuring execution time */
use std::time::Instant;

/* Interact with a running FM20 database. */


/*
From https://github.com/ThanosSiopoudis/FMScoutFramework/issues/1

Right, ok, here it goes:

You will need a few tools first:

Ollydbg
A good Hex editor that can handle process memory (HxD, 010 Editor or ArtMoney)

Now, if you know the way loads data already (and you do for both FM 2014 and FM 2015 as the code is already there and it doesn't change for updates), all you need is to fire up your editor.

Your clue is the way the Framework reads the data. You basically have to work your way backwards.

* Fire up Football Manager 2015, and the editor of your choice
* Start a brand new game, and switch back to the editor. Attach the editor to the fm process
* Convert a Club Name to an FM Hex String. To do this, open your hex editor and create a new document. Write the club's name by adding a space after every character. Now, replace the 20 to 00.

Example:

Chelsea
C     h     e     l     s     e     a
43 00 68 00 65 00 6C 00 73 00 65 00 61 00

1. Copy the hex string and do a search in the game's process memory. Keep searching until you find something that looks like what you're searching for. The correct match, should be preceded by 01 and the number of actual characters (07): 01 07 00 00 43 00 68 00 65 00 6C 00 73 00 65 00 61 00
2. Note down the address at the 01 byte. As an example: 0x289DA0B0
3. Do a search for a pointer to this address. If your editor doesn't give you an option to search for pointers, you need to reverse the address at every byte. (ex. B0 A0 9D 28). Do a new search for that.
4. You are looking for the club object, so the correct match should be at the right distance to the club's UID. The UID is double-written in the memory. It is always RowID - UID - UID.
5. You know the UID is at offset 0x8. It always is. So move your pointer to UID - 0x8 and get the address again.
6. Do a search for a pointer to this address.
7. The next thing we are looking for, is the array contents. You are basically looking for a bunch of memory pointers next to each other.
8. Once you find it, start scrolling to find the beginning of the array. An easier way to do this, would be to search for the first club in the database, called Albpetrol Patos something. Write down the address of the first pointer in the array.
9. Search for a pointer to this address. You are now looking for an array pointer. An array pointer looks like this: 0C F0 9A 30 20 F0 9A 30 20 F0 9A 30. The first part (0C F0 9A 30) is the pointer to the beginning of the array, and the next two parts (20 F0 9A 30 20 F0 9A 30) are two pointers next to each other that both point to the end of the array.
10. Take a note of the address at the beginning of the first pointer. Do a new search for a pointer to this address.
11. You shouldn't get too many results, but to make sure you're going the right way, with every search you should be moving backwards in the memory.
12. Once you find your pointer, take a note of the address, and subtract 0x40.
13. Take a note of the address, and again, look for a pointer.
14. Subtract 0x14, and take a note of the address (we know that Clubs are at offset 0x14 from the start of the object pointers)
15. Search for a new pointer to this address. Take a note, and ...
16. Search for a pointer to the address.
17. If everything went well, you are at the MainOffset! Take a note of the address, and subtract the process base address (you can figure this out by debugging the FMScoutFramework, put a breakpoint in file /VirtualMemory/Managers/GameManager.cs, line 171.

That's it! You can fork the project and create a new version file with all required attributes, then please do a pull request and I'll merge it in the main tree.

Another way, which is easier, but more time consuming, is to let the framework figure it out on its own. If it can't find a matching version, it will go in offset search mode, which will read the process and look for good candidates, and dump them in the Debug window of Visual Studio. It doesn't always work, but when it does, it is accurate. I've just pushed an update that makes the offset search compatible with FM15 (untested).


*/

static FM_PROCESS_NAME: &str = "fm.exe"; // name of the target process
const TARGET : &str = "Wadhah Zaidi";    // the string we want to look up
const  BUF_SIZE: usize = 4096 * 32;      // chunk size for remote scans
const SCAN_BASE: usize = 0x30000000;     // base address to start searching at

/* Find the PID for the fm.exe process */
fn find_fm_pid() -> process_memory::Pid
{
    let mut system = sysinfo::System::new_all();
    // First we update all information of our system struct.
    system.refresh_all();

    let mut fmpid : process_memory::Pid = 0;
    // Now let's print every process' id and name:
    for (pid, proc_) in system.get_processes() {
        if proc_.name() == FM_PROCESS_NAME
        {
            fmpid = *pid as u32;
        }
    }
    fmpid
}

/* Scan a given buf for the occurrence of our TARGET string 
 *
 * TODO: What if our target string only occurs partially at the end of the buf?
 */
fn scan(buf : [u8; BUF_SIZE], offset : usize) -> bool
{
    let s = String::from(TARGET);
    let target = s.as_bytes();

    for i in 0 .. BUF_SIZE - target.len() {
        if target == &buf[i .. i + target.len()] {
            println!("Found {}! Address = {:x} + {:x} = {:x}", s, offset, i, offset+i);
            return true;
        }
    }
    false
}

/*
 * TODO:
 * - reverse engineer player, club structs
 * - find players based on a list of names
 * - dump data
 * - import into Google Sheets
 */

fn main()
{
    let fmpid: Pid = find_fm_pid();
    if fmpid == 0
    {
        println!("ERROR: FM20 binary {} is not running.", FM_PROCESS_NAME);
        std::process::exit(1);
    }
    println!("FM20 Scan: Found running {} with PID {}.", FM_PROCESS_NAME, fmpid);

    let ts_start = Instant::now();

    let fmhandle = fmpid.try_into_process_handle().unwrap();
    let mut dm = DataMember::<[u8; BUF_SIZE]>::new(fmhandle);
    for offset in (SCAN_BASE..0xF0000000).step_by(BUF_SIZE)
    {
        dm.set_offset(vec![offset]);
        match dm.read() {
            Ok(buf) => {
                if scan(buf, offset) { break };
            },
            Err(_) => {},
        }
    }

    let duration = ts_start.elapsed();
    println!("Finished in {:?}", duration);
}
