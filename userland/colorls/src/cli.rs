//! Command-line parsing (clap) mapped onto the gem's option semantics.

use clap::Parser;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShowFilter {
    Dirs,
    Files,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sort {
    Name,
    Time,
    Size,
    Extension,
    None,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroupFirst {
    Dirs,
    Files,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisplayMode {
    Vertical,
    Horizontal,
    Long,
    OnePerLine,
    Tree,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Indicator {
    Slash,
    None,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReportMode {
    Short,
    Long,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ColorWhen {
    Always,
    Auto,
    Never,
}

#[derive(Debug, Clone)]
pub struct LongOpts {
    pub show_group: bool,
    pub show_user: bool,
    pub time_style: String,
    pub hard_links_count: bool,
    pub show_symbol_dest: bool,
    pub human_readable_size: bool,
}

impl Default for LongOpts {
    fn default() -> Self {
        LongOpts {
            show_group: true,
            show_user: true,
            time_style: String::new(),
            hard_links_count: true,
            show_symbol_dest: false,
            human_readable_size: true,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Options {
    pub all: bool,
    pub almost_all: bool,
    pub show: Option<ShowFilter>,
    pub sort: Sort,
    pub reverse: bool,
    pub group: Option<GroupFirst>,
    pub mode: DisplayMode,
    pub tree_depth: Option<i64>,
    pub show_git: bool,
    pub light: bool,
    pub color: ColorWhen,
    pub hyperlink: bool,
    pub show_inode: bool,
    pub indicator_style: Indicator,
    pub icons: bool,
    pub report: Option<ReportMode>,
    pub long: LongOpts,
    pub paths: Vec<String>,
}

#[derive(Parser, Debug)]
#[command(
    name = "colorls",
    disable_help_flag = true,
    disable_version_flag = true,
    disable_help_subcommand = true
)]
struct Raw {
    #[arg(short = 'a', long = "all")]
    all: bool,
    #[arg(short = 'A', long = "almost-all")]
    almost_all: bool,
    #[arg(short = 'd', long = "dirs")]
    dirs: bool,
    #[arg(short = 'f', long = "files")]
    files: bool,
    #[arg(long = "gs", visible_alias = "git-status")]
    gs: bool,
    #[arg(short = 'p')]
    slash: bool,
    #[arg(short = 'i', long = "inode")]
    inode: bool,
    #[arg(long = "report", num_args = 0..=1, default_missing_value = "long")]
    report: Option<String>,
    #[arg(long = "indicator-style", num_args = 0..=1, default_missing_value = "slash")]
    indicator_style: Option<String>,

    #[arg(long = "format")]
    format: Option<String>,
    #[arg(short = '1')]
    one: bool,
    #[arg(long = "tree", num_args = 0..=1, value_name = "DEPTH")]
    tree: Option<Option<i64>>,
    #[arg(short = 'x')]
    across: bool,
    #[arg(short = 'C')]
    columns: bool,
    #[arg(long = "without-icons")]
    without_icons: bool,

    #[arg(short = 'l', long = "long")]
    long: bool,
    #[arg(short = 'o')]
    long_no_group: bool,
    #[arg(short = 'g')]
    long_no_owner: bool,
    #[arg(short = 'G', long = "no-group")]
    no_group: bool,
    #[arg(long = "time-style")]
    time_style: Option<String>,
    #[arg(long = "no-hardlinks")]
    no_hardlinks: bool,
    #[arg(short = 'L')]
    deref: bool,
    #[arg(long = "non-human-readable")]
    non_human: bool,

    #[arg(long = "sd", visible_alias = "sort-dirs", visible_alias = "group-directories-first")]
    sd: bool,
    #[arg(long = "sf", visible_alias = "sort-files")]
    sf: bool,
    #[arg(short = 't')]
    sort_time: bool,
    #[arg(short = 'U')]
    no_sort: bool,
    #[arg(short = 'S')]
    sort_size: bool,
    #[arg(short = 'X')]
    sort_ext: bool,
    #[arg(long = "sort", value_name = "WORD")]
    sort_word: Option<String>,
    #[arg(short = 'r', long = "reverse")]
    reverse: bool,

    // Compatibility with ls (ignored): -h/--human-readable is always "on".
    #[arg(short = 'h', long = "human-readable")]
    human: bool,

    #[arg(long = "color", num_args = 0..=1, default_missing_value = "always")]
    color: Option<String>,
    #[arg(long = "light")]
    light: bool,
    #[arg(long = "dark")]
    dark: bool,
    #[arg(long = "hyperlink")]
    hyperlink: bool,

    #[arg(long = "help")]
    help: bool,
    #[arg(long = "version")]
    version: bool,

    #[arg(trailing_var_arg = false)]
    paths: Vec<String>,
}

/// Result of parsing: either run with options, or an early exit (help/version).
pub enum Parsed {
    Run(Box<Options>),
    Exit(i32),
}

/// Parse `argv` (without the program name already stripped is fine — clap
/// handles it) into [`Options`]. `stdout_tty` selects the default list mode.
pub fn parse(args: &[String], stdout_tty: bool) -> Parsed {
    // `colorls -h` (only -h args) shows help; otherwise -h is human-readable.
    let non_prog: Vec<&String> = args.iter().skip(1).collect();
    if !non_prog.is_empty() && non_prog.iter().all(|a| *a == "-h") {
        print_help();
        return Parsed::Exit(0);
    }

    let raw = match Raw::try_parse_from(args) {
        Ok(r) => r,
        Err(e) => {
            // Mimic the gem's parse-error behavior (stderr + exit 2), but let
            // clap print its own help/version-style errors for --help misuse.
            eprint!("colorls: {e}");
            eprintln!("See 'colorls --help'.");
            return Parsed::Exit(2);
        }
    };

    if raw.help {
        print_help();
        return Parsed::Exit(0);
    }
    if raw.version {
        println!("1.5.0");
        return Parsed::Exit(0);
    }

    // --- mode -----------------------------------------------------------
    let mut mode = if stdout_tty {
        DisplayMode::Vertical
    } else {
        DisplayMode::OnePerLine
    };
    if let Some(fmt) = raw.format.as_deref() {
        match fmt {
            "across" | "horizontal" => mode = DisplayMode::Horizontal,
            "vertical" => mode = DisplayMode::Vertical,
            "long" => mode = DisplayMode::Long,
            "single-column" => mode = DisplayMode::OnePerLine,
            _ => {}
        }
    }
    if raw.columns {
        mode = DisplayMode::Vertical;
    }
    if raw.across {
        mode = DisplayMode::Horizontal;
    }
    if raw.one {
        mode = DisplayMode::OnePerLine;
    }
    if raw.long || raw.long_no_group || raw.long_no_owner {
        mode = DisplayMode::Long;
    }
    let mut tree_depth = None;
    if let Some(t) = raw.tree {
        mode = DisplayMode::Tree;
        tree_depth = t; // None => unlimited, Some(n) => depth n
    }

    // --- sort (fixed precedence; see README) ----------------------------
    let sort = if raw.no_sort {
        Sort::None
    } else if let Some(w) = raw.sort_word.as_deref() {
        match w {
            "none" => Sort::None,
            "time" => Sort::Time,
            "size" => Sort::Size,
            "extension" => Sort::Extension,
            _ => Sort::Name,
        }
    } else if raw.sort_ext {
        Sort::Extension
    } else if raw.sort_size {
        Sort::Size
    } else if raw.sort_time {
        Sort::Time
    } else {
        Sort::Name
    };

    // --- group ----------------------------------------------------------
    let group = if raw.sd {
        Some(GroupFirst::Dirs)
    } else if raw.sf {
        Some(GroupFirst::Files)
    } else {
        None
    };

    // --- show filter ----------------------------------------------------
    let show = if raw.dirs {
        Some(ShowFilter::Dirs)
    } else if raw.files {
        Some(ShowFilter::Files)
    } else {
        None
    };

    // --- indicator style ------------------------------------------------
    let indicator_style = match raw.indicator_style.as_deref() {
        Some("none") => Indicator::None,
        _ if raw.slash => Indicator::Slash,
        Some("slash") => Indicator::Slash,
        _ => Indicator::Slash, // gem default
    };

    // --- report ---------------------------------------------------------
    let report = match raw.report.as_deref() {
        Some("short") => Some(ReportMode::Short),
        Some("long") => Some(ReportMode::Long),
        Some(_) => Some(ReportMode::Long),
        None => None,
    };

    // --- color ----------------------------------------------------------
    let color = match raw.color.as_deref() {
        Some("never") => ColorWhen::Never,
        Some("always") => ColorWhen::Always,
        Some("auto") => ColorWhen::Auto,
        Some(_) => ColorWhen::Always,
        None => ColorWhen::Auto,
    };

    // --- long style options ---------------------------------------------
    let mut long = LongOpts::default();
    if raw.long_no_group || raw.no_group {
        long.show_group = false;
    }
    if raw.long_no_owner {
        long.show_user = false;
    }
    if let Some(ts) = raw.time_style {
        long.time_style = ts;
    }
    if raw.no_hardlinks {
        long.hard_links_count = false;
    }
    if raw.deref {
        long.show_symbol_dest = true;
    }
    if raw.non_human {
        long.human_readable_size = false;
    }

    // `--all` and `--tree` don't combine; use almost-all instead (gem FIXME).
    let (mut all, mut almost_all) = (raw.all, raw.almost_all);
    if mode == DisplayMode::Tree && all {
        almost_all = true;
        all = false;
    }

    Parsed::Run(Box::new(Options {
        all,
        almost_all,
        show,
        sort,
        reverse: raw.reverse,
        group,
        mode,
        tree_depth,
        show_git: raw.gs,
        light: raw.light && !raw.dark,
        color,
        hyperlink: raw.hyperlink,
        show_inode: raw.inode,
        indicator_style,
        icons: !raw.without_icons,
        report,
        long,
        paths: raw.paths,
    }))
}

fn print_help() {
    print!(
        "Usage:  colorls [OPTION]... [FILE]...\n\n\
         A fast Rust reimplementation of colorls.\n\n\
         common options:\n  \
         -a, --all                  do not ignore entries starting with .\n  \
         -A, --almost-all           do not list . and ..\n  \
         -d, --dirs                 show only directories\n  \
         -f, --files                show only files\n  \
         --gs, --git-status         show git status for each file\n  \
         -p                         append / indicator to directories\n  \
         -i, --inode                show inode number\n  \
         --report[=WORD]            show report: short, long (default)\n  \
         --indicator-style[=STYLE]  none, slash (-p) (default)\n\n\
         format options:\n  \
         --format=WORD              across (-x), long (-l), single-column (-1), vertical (-C)\n  \
         -1                         list one file per line\n  \
         --tree[=DEPTH]             shows tree view of the directory\n  \
         -x                         list entries by lines instead of by columns\n  \
         -C                         list entries by columns instead of by lines\n  \
         --without-icons            list entries without icons\n\n\
         long-format options:\n  \
         -l, --long                 use a long listing format\n  \
         -o                         long listing without group information\n  \
         -g                         long listing without owner information\n  \
         -G, --no-group             show no group information\n  \
         --time-style=FORMAT        use time display format\n  \
         --no-hardlinks             show no hard links count\n  \
         -L                         show symlink destination info\n  \
         --non-human-readable       show file sizes in bytes only\n\n\
         sorting options:\n  \
         --sd, --sort-dirs, --group-directories-first\n  \
         --sf, --sort-files\n  \
         -t                         sort by modification time, newest first\n  \
         -U                         do not sort\n  \
         -S                         sort by file size, largest first\n  \
         -X                         sort by file extension\n  \
         --sort=WORD                none, size (-S), time (-t), extension (-X)\n  \
         -r, --reverse              reverse order while sorting\n\n\
         general options:\n  \
         -h, --human-readable       ignored (always active)\n  \
         --color[=WHEN]             auto, always (default if omitted), never\n  \
         --light                    use light color scheme\n  \
         --dark                     use dark color scheme\n  \
         --hyperlink                emit terminal hyperlinks\n  \
         --help                     prints this help\n  \
         --version                  show version\n"
    );
}
