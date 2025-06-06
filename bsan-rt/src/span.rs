#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct SpanData(usize);

impl SpanData {
    pub fn new() -> SpanData {
        SpanData(0)
    }
}

#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct Span(usize);

impl Span {
    pub fn new() -> Span {
        Span(0)
    }
    // Returns a DummySpanData with inner zero
    pub fn data(self) -> Span {
        Span::new()
    }
}

impl From<SpanData> for Span {
    fn from(val: SpanData) -> Self {
        Span(val.0)
    }
}

impl From<Span> for SpanData {
    fn from(val: Span) -> Self {
        SpanData(val.0)
    }
}
