#[derive(Debug, Clone, Default)]
pub struct MinHeap<T> {
    data: Vec<T>,
}

impl<T> MinHeap<T>
where
    T: Ord + Sized + Send + 'static,
{
    pub fn new(cap: usize) -> Self {
        Self {
            data: Vec::with_capacity(cap),
        }
    }

    pub fn from<const N: usize>(arr: [T; N]) -> Self {
        let mut heap = MinHeap {
            data: Vec::from(arr),
        };
        heap.build_min_heap();
        heap
    }

    pub fn insert(&mut self, elem: T) {
        self.data.push(elem);
        let heap_size = self.data.len();
        let mut i = heap_size - 1;

        // if the new node is smaller than the parent, we bubble it up to the parents position
        // if the node is at position 0, we cant compare its non existant parents
        while i > 0 && self.data[i] < self.data[parent(i)] {
            self.data.swap(parent(i), i);
            i = parent(i);
        }
    }

    pub fn pop(&mut self) -> Option<T> {
        if self.data.is_empty() {
            return None;
        }
        let last_elem = self.data.len() - 1;

        self.data.swap(0, last_elem);
        let min = self.data.remove(last_elem);

        self.min_heapify(0);

        Some(min)
    }

    pub fn peek(&self) -> Option<&T> {
        self.data.first()
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    pub fn clear(&mut self) {
        self.data.clear()
    }

    fn min_heapify(&mut self, idx: usize) {
        let heap_size = self.data.len();
        let a = &self.data;

        let l = left(idx);
        let r = right(idx);
        let mut smallest;

        if l < heap_size && a[l] < a[idx] {
            smallest = l;
        } else {
            smallest = idx;
        }

        if r < heap_size && a[r] < a[smallest] {
            smallest = r;
        }

        if smallest != idx {
            self.data.swap(idx, smallest);
            self.min_heapify(smallest);
        }
    }

    fn build_min_heap(&mut self) {
        let heap_size = self.data.len();
        let mut i = heap_size / 2;
        loop {
            self.min_heapify(i);

            let (sub, underflow) = i.overflowing_sub(1);
            if !underflow {
                i = sub;
            } else {
                break;
            }
        }
    }
}

fn parent(idx: usize) -> usize {
    (idx - 1) / 2
}
fn left(idx: usize) -> usize {
    (idx * 2) + 1
}
fn right(idx: usize) -> usize {
    (idx * 2) + 2
}

#[derive(Debug)]
pub struct MinHeapIter<T> {
    cound: usize,
    heap: MinHeap<T>,
}

impl<T> Iterator for MinHeapIter<T>
where
    T: Ord,
{
    type Item = T;

    fn next(&mut self) -> Option<Self::Item> {
        todo!()
    }
}

#[cfg(test)]
mod heap_test {
    use super::*;

    fn assert_sorted_asc(mut heap: MinHeap<i32>) {
        let mut prev = i32::MIN;
        while let Some(val) = heap.pop() {
            assert!(val >= prev, "out of order: got {val} after {prev}");
            prev = val;
        }
    }

    #[test]
    fn new_heap_is_empty() {
        let h: MinHeap<i32> = MinHeap::new(16);
        assert!(h.is_empty());
        assert_eq!(h.len(), 0);
        assert_eq!(h.peek(), None);
    }

    #[test]
    fn insert_single_element() {
        let mut h = MinHeap::new(4);
        h.insert(42);
        assert_eq!(h.len(), 1);
        assert_eq!(h.peek(), Some(&42));
    }

    #[test]
    fn insert_ascending_keeps_min_at_root() {
        let mut h = MinHeap::new(8);
        for v in [10, 20, 30, 40] {
            h.insert(v);
        }
        assert_eq!(h.peek(), Some(&10));
    }

    #[test]
    fn insert_descending_keeps_min_at_root() {
        let mut h = MinHeap::new(8);
        for v in [40, 30, 20, 10] {
            h.insert(v);
        }
        assert_eq!(h.peek(), Some(&10));
    }

    #[test]
    fn insert_random_order_keeps_min_at_root() {
        let mut h = MinHeap::new(8);
        for v in [5, 3, 8, 1, 9, 2] {
            h.insert(v);
        }
        assert_eq!(h.peek(), Some(&1));
    }

    #[test]
    fn pop_empty_returns_none() {
        let mut h: MinHeap<i32> = MinHeap::new(4);
        assert_eq!(h.pop(), None);
    }

    #[test]
    fn pop_single_element() {
        let mut h = MinHeap::new(4);
        h.insert(7);
        assert_eq!(h.pop(), Some(7));
        assert!(h.is_empty());
    }

    #[test]
    fn pop_returns_elements_in_sorted_order() {
        let mut h = MinHeap::new(8);
        for v in [5, 3, 8, 1, 9, 2] {
            h.insert(v);
        }
        assert_eq!(h.pop(), Some(1));
        assert_eq!(h.pop(), Some(2));
        assert_eq!(h.pop(), Some(3));
        assert_eq!(h.pop(), Some(5));
        assert_eq!(h.pop(), Some(8));
        assert_eq!(h.pop(), Some(9));
        assert_eq!(h.pop(), None);
    }

    #[test]
    fn from_array_has_correct_length() {
        let h = MinHeap::from([4, 1, 7, 3, 9]);
        assert_eq!(h.len(), 5);
    }

    #[test]
    fn from_array_peek_is_minimum() {
        let h = MinHeap::from([4, 1, 7, 3, 9]);
        assert_eq!(h.peek(), Some(&1));
    }

    #[test]
    fn from_array_pops_in_sorted_order() {
        let h = MinHeap::from([4, 1, 7, 3, 9, 2, 6]);
        assert_sorted_asc(h);
    }

    #[test]
    fn from_already_sorted_array() {
        let h = MinHeap::from([1, 2, 3, 4, 5]);
        assert_sorted_asc(h);
    }

    #[test]
    fn from_reverse_sorted_array() {
        let h = MinHeap::from([5, 4, 3, 2, 1]);
        assert_sorted_asc(h);
    }

    #[test]
    fn from_single_element_array() {
        let mut h = MinHeap::from([99]);
        assert_eq!(h.peek(), Some(&99));
        assert_eq!(h.pop(), Some(99));
        assert!(h.is_empty());
    }

    #[test]
    fn handles_duplicate_values() {
        let h = MinHeap::from([3, 1, 4, 1, 5, 9, 2, 6, 5]);
        assert_sorted_asc(h);
    }

    #[test]
    fn handles_all_identical_values() {
        let h = MinHeap::from([7, 7, 7, 7]);
        assert_sorted_asc(h);
    }

    #[test]
    fn handles_negative_values() {
        let h = MinHeap::from([-3, 5, -10, 0, 7]);
        assert_sorted_asc(h);
    }

    #[test]
    fn large_heap_sorted_output() {
        use std::cmp::Reverse;
        use std::collections::BinaryHeap;

        let data: Vec<i32> = (0..200).map(|x| (x * 37 + 13) % 97).collect();
        let arr: [i32; 200] = data.clone().try_into().unwrap();
        let heap = MinHeap::from(arr);

        // reference answer via std's max-heap reversed
        let mut std_heap: BinaryHeap<Reverse<i32>> = data.iter().map(|&x| Reverse(x)).collect();
        let expected: Vec<i32> = std::iter::from_fn(|| std_heap.pop())
            .map(|Reverse(v)| v)
            .collect();

        let got: Vec<i32> = {
            let mut h = heap;
            std::iter::from_fn(|| h.pop()).collect()
        };

        assert_eq!(got, expected);
    }
}
