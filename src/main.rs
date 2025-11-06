use std::collections::HashSet;
use std::fs::File;
use std::io::{Error, ErrorKind};
use clap::{ Parser};
use std::process::exit;
use std::{fs, ptr};
use std::os::fd::AsRawFd;
use chrono::{DateTime, Utc};
use libc::{mincore, mmap, munmap, off_t, sysconf, MAP_SHARED, PROT_READ, _SC_PAGESIZE};
use procfs::process::MMapPath;

#[derive(Debug, Parser)]
struct Args {
    #[clap(long = "pid",)]
    pid_flag: Option<i32>,
    #[clap(long = "top")]
    top_flag: i32,

    #[clap(long="terse",action=clap::ArgAction::SetTrue)]
    terse_flag: bool,
    #[clap(long="nohdr",action=clap::ArgAction::SetTrue)]
    nohdr_flag: bool,
    #[clap(long="json",action=clap::ArgAction::SetTrue)]
    json_flag: bool,
    #[clap(long="unicode",action=clap::ArgAction::SetTrue)]
    unicode_flag: bool,

    #[clap(long="plain",action=clap::ArgAction::SetTrue)]
    plain_flag: bool,
    #[clap(long="pps",action=clap::ArgAction::SetTrue)]
    pps_flag: bool,
    #[clap(long="histo",action=clap::ArgAction::SetTrue)]
    histo_flag: bool,
    #[clap(long="bname",action=clap::ArgAction::SetTrue)]
    bname_flag: bool,

    files: Vec<String>,
}

#[derive(Debug)]
pub struct PcStatus {

    pub name: String,      // file name as specified on command line


    pub size: i64,         // file size in bytes


    pub timestamp: DateTime<Utc>, // time right before calling mincore


    pub mtime: DateTime<Utc>,     // last modification time of the file


    pub pages: i32,        // total memory pages


    pub cached: i32,       // number of pages that are cached


    pub uncached: i32,     // number of pages that are not cached


    pub percent: f64,      // percentage of pages cached


    pub pp_stat: Vec<bool>, // per-page status, true if cached, false otherwise
}

pub fn get_pc_status(fname: &str) -> Result<PcStatus, Error> {
    let mut pcs = PcStatus {
        name: fname.to_string(),
        size: 0,
        timestamp: Utc::now(), // 默认值，稍后更新
        mtime: Utc::now(),     // 默认值，稍后更新
        pages: 0,
        cached: 0,
        uncached: 0,
        percent: 0.0,
        pp_stat: Vec::new(),
    };

    let file = File::open(fname)?;
    let fd = file.as_raw_fd();

    // 获取文件元数据
    let metadata = fs::metadata(fname)?;
    if metadata.is_dir() {
        return Err(Error::new(ErrorKind::InvalidInput, "file is a directory"));
    }

    pcs.size = metadata.len() as i64;
    pcs.mtime = metadata.modified()?.into();

    // mmap 文件
    let map = unsafe {
        mmap(
            ptr::null_mut(),
            pcs.size as usize,
            PROT_READ,
            MAP_SHARED,
            fd,
            0 as off_t,
        )
    };
    if map == libc::MAP_FAILED {
        return Err(Error::last_os_error());
    }

    // 获取系统页面大小
    let page_size = unsafe { sysconf(_SC_PAGESIZE) } as usize;

    // 计算页面数
    pcs.pages = ((pcs.size as usize + page_size - 1) / page_size) as i32;

    // 分配 mincore 向量
    let vec_size = pcs.pages as usize;
    let mut vec: Vec<u8> = vec![0; vec_size];

    // 更新时间戳（mincore 前）
    pcs.timestamp = Utc::now();

    // 调用 mincore
    let ret = unsafe { mincore(map, pcs.size as usize, vec.as_mut_ptr()) };
    if ret != 0 {
        unsafe { munmap(map, pcs.size as usize) };
        return Err(Error::last_os_error());
    }

    // 清理 mmap
    unsafe { munmap(map, pcs.size as usize) };

    // 处理 mincore 结果：转换为 Vec<bool>
    pcs.pp_stat = Vec::with_capacity(vec_size);
    for &byte in &vec {
        let is_cached = (byte & 1) == 1;
        pcs.pp_stat.push(is_cached);
        if is_cached {
            pcs.cached += 1;
        }
    }

    pcs.uncached = pcs.pages - pcs.cached;
    pcs.percent = if pcs.pages > 0 {
        (pcs.cached as f64 / pcs.pages as f64) * 100.0
    } else {
        0.0
    };

    Ok(pcs)
}

fn top(args:&Args) -> Result<(), Box<dyn std::error::Error>>{
    let fpaths:HashSet<_> = procfs::process::all_processes()?
        .filter_map(|p|p.ok())
        .filter(|p|{
            if let Ok(s) = p.stat(){
                s.rss != 0
            }else { false }
        })
        .map(|p|{
            if let Ok(m) =  p.maps(){
                let fpaths: Vec<_> = m.0.iter()
                    .filter_map(|f| {
                        if let MMapPath::Path(s) =  f.pathname.clone() {
                           Some(s)
                        }else { None }
                    })
                    .collect();
                fpaths
            }else { Vec::new() }
        })
        .collect::<Vec<_>>()
        .into_iter().flatten()
        .filter(|c|c.is_file())
        .collect::<HashSet<_>>();

    let s  = fpaths.iter()
        .filter(|c|c.exists())
        .filter_map(|f|{
            Some(get_pc_status(f.as_path().to_str().unwrap()).unwrap())
        })
        .collect::<Vec<_>>();


    for ss in s{
        println!("{:?}\t{:?}\t{:?}\t{:?}\t{:?}\t{:?}",ss.name,ss.size,ss.pages,ss.cached,ss.uncached, ss.percent);
    }


    Ok(())

}

fn main() {
    let args = Args::parse();
    println!("{:?}", args);


    if args.top_flag != 0 {
        let _ = top(&args);
        exit(0);
    }

}
