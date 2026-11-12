//! Grid layout, ported from the gem's `Layout`/`VerticalLayout`/`HorizontalLayout`.
//!
//! Produces the list of display rows (as indices into the contents) plus the
//! per-column max widths used for padding, matching the gem byte-for-byte.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Vertical,
    Horizontal,
    Single,
}

/// Returns `(rows, column_widths)` where each row is a list of content indices.
pub fn compute(mode: Mode, item_widths: &[usize], screen_width: usize) -> (Vec<Vec<usize>>, Vec<usize>) {
    let n = item_widths.len();
    if n == 0 {
        return (Vec::new(), Vec::new());
    }
    match mode {
        Mode::Single => ((0..n).map(|i| vec![i]).collect(), vec![1]),
        Mode::Vertical => vertical(item_widths, screen_width),
        Mode::Horizontal => horizontal(item_widths, screen_width),
    }
}

/// Binary-search for the chunk size, exactly like `Layout#chunk_size`.
///
/// `column_widths(mid)` is always computed from the *original* item widths
/// (the gem only reassigns `@max_widths` on the terminal branch).
fn chunk_size<F>(item_widths: &[usize], screen_width: usize, column_widths: F) -> (usize, Vec<usize>)
where
    F: Fn(usize) -> (usize, Vec<usize>),
{
    let min_size = *item_widths.iter().min().unwrap();
    let mut max_chunks = (screen_width / min_size.max(1)).max(1);
    max_chunks = max_chunks.min(item_widths.len());
    let mut min_chunks = 1usize;

    loop {
        let mid = ((max_chunks + min_chunks) as f64 / 2.0).ceil() as usize;
        let (size, widths) = column_widths(mid);
        let sum: usize = widths.iter().sum();
        if min_chunks < max_chunks && sum > screen_width {
            max_chunks = mid - 1;
        } else if min_chunks < mid {
            min_chunks = mid;
        } else {
            return (size, widths);
        }
    }
}

fn vertical(item_widths: &[usize], screen_width: usize) -> (Vec<Vec<usize>>, Vec<usize>) {
    let n = item_widths.len();
    let column_widths = |mid: usize| -> (usize, Vec<usize>) {
        let rows_per_col = (n as f64 / mid as f64).ceil() as usize;
        let cols: Vec<usize> = item_widths
            .chunks(rows_per_col)
            .map(|c| *c.iter().max().unwrap())
            .collect();
        (rows_per_col, cols)
    };
    let (rows_per_col, col_widths) = chunk_size(item_widths, screen_width, column_widths);

    // Build columns of indices, pad the last to `rows_per_col` with None.
    let columns: Vec<Vec<Option<usize>>> = (0..n)
        .collect::<Vec<_>>()
        .chunks(rows_per_col)
        .map(|c| {
            let mut v: Vec<Option<usize>> = c.iter().map(|&i| Some(i)).collect();
            while v.len() < rows_per_col {
                v.push(None);
            }
            v
        })
        .collect();

    // Transpose columns -> rows, compacting the trailing None padding.
    let mut rows = Vec::with_capacity(rows_per_col);
    for r in 0..rows_per_col {
        let row: Vec<usize> = columns.iter().filter_map(|col| col[r]).collect();
        if !row.is_empty() {
            rows.push(row);
        }
    }
    (rows, col_widths)
}

fn horizontal(item_widths: &[usize], screen_width: usize) -> (Vec<Vec<usize>>, Vec<usize>) {
    let n = item_widths.len();
    let column_widths = |mid: usize| -> (usize, Vec<usize>) {
        let first_len = item_widths.chunks(mid).next().map(|c| c.len()).unwrap_or(0);
        let rows: Vec<Vec<usize>> = item_widths
            .chunks(mid)
            .map(|c| {
                let mut v = c.to_vec();
                while v.len() < first_len {
                    v.push(0); // pad last row with 0, like `fill(0, ...)`
                }
                v
            })
            .collect();
        // Column maxima = transpose then max.
        let cols: Vec<usize> = (0..first_len)
            .map(|c| rows.iter().map(|r| r[c]).max().unwrap_or(0))
            .collect();
        (mid, cols)
    };
    let (per_row, col_widths) = chunk_size(item_widths, screen_width, column_widths);

    let rows: Vec<Vec<usize>> = (0..n)
        .collect::<Vec<_>>()
        .chunks(per_row)
        .map(|c| c.to_vec())
        .collect();
    (rows, col_widths)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_column_is_one_per_row() {
        let (rows, widths) = compute(Mode::Single, &[10, 20, 30], 80);
        assert_eq!(rows, vec![vec![0], vec![1], vec![2]]);
        assert_eq!(widths, vec![1]);
    }

    #[test]
    fn empty_input() {
        let (rows, widths) = compute(Mode::Vertical, &[], 80);
        assert!(rows.is_empty());
        assert!(widths.is_empty());
    }

    #[test]
    fn vertical_fills_down_columns() {
        // 4 items width 10 each, wide screen -> one row of 4 columns.
        let (rows, _w) = compute(Mode::Vertical, &[10, 10, 10, 10], 100);
        assert_eq!(rows, vec![vec![0, 1, 2, 3]]);
    }

    #[test]
    fn vertical_wraps_when_narrow() {
        // Narrow screen forces a single column: items stack top-to-bottom.
        let (rows, _w) = compute(Mode::Vertical, &[50, 50, 50], 60);
        assert_eq!(rows, vec![vec![0], vec![1], vec![2]]);
    }

    #[test]
    fn horizontal_fills_across_rows() {
        let (rows, _w) = compute(Mode::Horizontal, &[10, 10, 10, 10], 100);
        assert_eq!(rows, vec![vec![0, 1, 2, 3]]);
    }
}
