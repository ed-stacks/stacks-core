use std::cmp;
use std::path::Path;

use plotters::prelude::*;

use crate::db::BenchDatabase;

pub fn write_plot(
    db: &mut BenchDatabase,
    path: impl AsRef<Path>,
) -> Result<(), Box<dyn std::error::Error>> {
    let metrics = db.iter_metrics()?;

    let (intp_len, wasm_len) =
        metrics
            .iter()
            .fold((0, 0), |(intp, wasm), metric| match metric.wasm {
                false => (intp + 1, wasm),
                true => (intp, wasm + 1),
            });

    let mut intp = Vec::with_capacity(intp_len);
    let mut wasm = Vec::with_capacity(wasm_len);

    let mut min_calls = u64::MAX;
    let mut max_calls = 0;
    let mut min_runtime = f64::MAX;
    let mut max_runtime = 0.0f64;

    metrics.into_iter().for_each(|metric| {
        let series = match metric.wasm {
            false => &mut intp,
            true => &mut wasm,
        };

        series.push(Point {
            calls: metric.calls,
            avg: metric.avg,
            var: metric.var,
        });

        min_calls = cmp::min(metric.calls, min_calls);
        max_calls = cmp::max(metric.calls, max_calls);
        min_runtime = min_runtime.min(metric.avg - metric.var.sqrt());
        max_runtime = max_runtime.max(metric.avg + metric.var.sqrt());
    });

    let root = SVGBackend::new(&path, (2100, 900)).into_drawing_area();

    let mut chart = ChartBuilder::on(&root)
        .caption("Clarity Wasm Benchmark", ("sans-serif", 60))
        .margin(10)
        .set_label_area_size(LabelAreaPosition::Left, 40)
        .set_label_area_size(LabelAreaPosition::Bottom, 40)
        .build_cartesian_2d(min_calls - 1..max_calls + 1, min_runtime..max_runtime)?;

    chart.configure_mesh().draw()?;

    chart
        .draw_series(LineSeries::new(
            intp.iter().map(|point| (point.calls, point.avg)),
            GREEN,
        ))?
        .label("Interpreter")
        .legend(|(x, y)| PathElement::new(vec![(x, y), (x + 20, y)], GREEN));
    chart
        .draw_series(LineSeries::new(
            wasm.iter().map(|point| (point.calls, point.avg)),
            BLUE,
        ))?
        .label("Wasm")
        .legend(|(x, y)| PathElement::new(vec![(x, y), (x + 20, y)], BLUE));

    chart
        .configure_series_labels()
        .background_style(WHITE.filled())
        .draw()?;

    root.present()?;

    Ok(())
}

struct Point {
    calls: u64,
    avg: f64,
    var: f64,
}
