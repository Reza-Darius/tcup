#[derive(Debug, Clone)]
pub struct MinHeap<T> {
    data: Vec<T>,
}

impl<T> MinHeap<T>
where
    T: Ord,
{
    /// does it satisfy the heap condition?
    fn is_min_heap(&self, idx: usize) -> bool {
        self.data[parent(idx)] <= self.data[idx]
    }

    pub fn new(cap: usize) -> Self {
        Self {
            data: Vec::with_capacity(cap),
        }
    }

    fn parent(&self, idx: usize) -> &T {
        &self.data[idx >> 1]
    }

    fn left(&self, idx: usize) -> &T {
        &self.data[idx << 1]
    }

    fn right(&self, idx: usize) -> &T {
        &self.data[(idx << 1) + 1]
    }
}

fn parent(idx: usize) -> usize {
    idx >> 1
}
fn left(idx: usize) -> usize {
    idx << 1
}
fn right(idx: usize) -> usize {
    (idx << 1) + 1
}
