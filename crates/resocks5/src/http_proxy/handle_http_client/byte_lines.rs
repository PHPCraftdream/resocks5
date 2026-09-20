pub(super) fn find_double_crlf(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

/// Lazy iterator over the CRLF-delimited lines of a byte block. Same
/// enumeration as the former collect-a-`Vec<&[u8]>`-of-all-lines loop,
/// minus the line table (R6-06): no allocation proportional to the
/// header count. When no `\r\n` remains, the remaining slice is yielded
/// once; an exhausted (empty) block yields nothing.
pub(crate) struct ByteLines<'a> {
    pub(crate) rest: &'a [u8],
}

impl<'a> Iterator for ByteLines<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<Self::Item> {
        if self.rest.is_empty() {
            return None;
        }
        match self.rest.windows(2).position(|w| w == b"\r\n") {
            Some(pos) => {
                let line = &self.rest[..pos];
                self.rest = &self.rest[pos + 2..];
                Some(line)
            }
            None => {
                let line = self.rest;
                self.rest = &[];
                Some(line)
            }
        }
    }
}
