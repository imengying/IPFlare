const INDENT_PREFIX: &str = "   ";

/// Console output with two behaviours: informational lines on stdout that
/// `quiet` can suppress, and warnings on stderr that always print.
pub struct PP {
    quiet: bool,
    indent: usize,
}

impl PP {
    pub fn new(quiet: bool) -> Self {
        Self { quiet, indent: 0 }
    }

    #[cfg(test)]
    pub fn default_pp() -> Self {
        Self::new(false)
    }

    pub fn indent(&self) -> PP {
        PP {
            quiet: self.quiet,
            indent: self.indent + 1,
        }
    }

    /// Progress and status output, suppressed by `quiet`.
    pub fn infof(&self, msg: &str) {
        if !self.quiet {
            println!("{}{msg}", INDENT_PREFIX.repeat(self.indent));
        }
    }

    /// Problems the operator needs to see, so never suppressed. Goes to stderr
    /// to keep it separable from the normal output stream.
    pub fn warningf(&self, msg: &str) {
        eprintln!("{}{msg}", INDENT_PREFIX.repeat(self.indent));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `quiet` gates `infof`; `warningf` bypasses it.
    #[test]
    fn quiet_flag_is_recorded() {
        assert!(PP::new(true).quiet);
        assert!(!PP::new(false).quiet);
        assert!(!PP::default_pp().quiet);
    }

    /// Nested indent levels accumulate and carry `quiet` down, which is what
    /// the config summary relies on.
    #[test]
    fn indent_nests_and_preserves_quiet() {
        let pp = PP::new(true);
        assert_eq!(pp.indent, 0);
        let child = pp.indent();
        assert_eq!(child.indent, 1);
        assert_eq!(child.indent().indent, 2);
        assert!(child.quiet);
    }
}
