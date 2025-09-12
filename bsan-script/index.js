let showMiri = false;

const createCharts = (architecture, benchmark_with_suffix) => {
  const chartsDiv = document.getElementById("charts");
  chartsDiv.innerHTML = ""; // Clear previous charts

  const archData = window.benchmarkData[architecture];

  if (!archData) {
    chartsDiv.innerHTML = `<p>No data found for architecture: ${architecture}</p>`;
    return;
  }

  const data = archData[benchmark_with_suffix];

  if (!data) {
    chartsDiv.innerHTML = `<p>No data found for benchmark: ${benchmark_with_suffix}</p>`;
    return;
  }

  const benchmark = benchmark_with_suffix.replace("-results", "");

  const tool_map = {
    [`./target/release/${benchmark}`]: "native",
    [`./${benchmark}`]: "BSAN",
    [`cargo +nightly miri run -p programs --bin ${benchmark}`]: "Miri",
  };

  const calculate_tool_transform = {
    "calculate": JSON.stringify(tool_map) + "[datum.command]",
    "as": "Tool"
  };

  const baseSpec = {
    "$schema": "https://vega.github.io/schema/vega-lite/v6.json",
    "width": 600,
    "height": 400,
    "data": {
      "values": data.results
    },
    "transform": [
      {"flatten": ["times"]},
      calculate_tool_transform,
      {"filter": showMiri ? "datum.Tool !== null" : "datum.Tool !== 'Miri'"}
    ]
  };

  const boxPlotSpec = {
    ...baseSpec,
    "title": "Benchmark Execution Time Comparison",
    "mark": {
      "type": "boxplot",
      "extent": "min-max",
      "size": 50,
      "box": {
        "stroke": "black",
        "strokeWidth": 2
      },
      "median": {
        "strokeWidth": 3
      },
      "color": {
        "gradient": "linear",
        "stops": [
          { "offset": 0, "color": "#F6D28C" },
          { "offset": 1, "color": "#B22222" }
        ]
      }
    },
    "encoding": {
      "x": {
        "field": "Tool",
        "type": "nominal",
        "title": "Tool",
        "sort": {"op": "median", "field": "times", "order": "ascending"}
      },
      "y": {
        "field": "times",
        "type": "quantitative",
        "title": "Execution Time (s)",
        "scale": {"type": "log"},
        "axis": {"format": ".3s"}
      }
    }
  };

  const scatterPlotSpec = {
    ...baseSpec,
    "title": "Benchmark Execution Time Comparison (Native vs. BSAN)",
    "transform": [
      {"flatten": ["times"]},
      calculate_tool_transform,
      {"filter": "datum.Tool === 'native' || datum.Tool === 'BSAN'"}
    ],
    "layer": [
      {
        "mark": {
          "type": "point",
          "opacity": 0.6,
          "filled": true,
          "stroke": "black",
          "strokeWidth": 0.5
        },
        "encoding": {
          "color": {
            "field": "Tool",
            "type": "nominal",
            "scale": {"scheme": "tableau10"},
            "legend": {
              "title": "Tool",
              "orient": "bottom",
              "direction": "horizontal"
            }
          },
          "tooltip": [
            {"field": "Tool", "type": "nominal", "title": "Test"},
            {"field": "times", "type": "quantitative", "format": ".4f", "title": "Time (s)"}
          ]
        }
      },
      {
        "mark": {
          "type": "rule",
          "color": "skyblue",
          "opacity": 0.7,
          "size": 3
        },
        "encoding": {
          "x": {
            "aggregate": "mean",
            "field": "times"
          }
        }
      }
    ],
    "encoding": {
      "y": {
        "field": "Tool",
        "type": "nominal",
        "title": "Tool",
        "sort": {"op": "median", "field": "times", "order": "ascending"}
      },
      "x": {
        "field": "times",
        "type": "quantitative",
        "title": "Execution Time (s)",
        "scale": {"type": "linear", "domain": [0, 0.015]},
        "axis": {"format": ".3s"}
      }
    }
  };

  const timeSeriesSpec = {
    ...baseSpec,
    "title": "Execution Time per Run with Average",
    "transform": [
      ...baseSpec.transform,
      {
        "window": [{"op": "row_number", "as": "run_number"}],
        "groupby": ["Tool"]
      }
    ],
    "layer": [
      {
        "mark": {
          "type": "point",
          "filled": true,
          "opacity": 0.3
        },
        "encoding": {
          "x": {
            "field": "run_number",
            "type": "quantitative",
            "title": "Run Number",
            "axis": {
              "labelAngle": 0
            }
          },
          "y": {
            "field": "times",
            "type": "quantitative",
            "title": "Execution Time (s)",
            "scale": {"zero": false}
          },
          "color": {
            "field": "Tool",
            "type": "nominal",
            "title": "Tool"
          }
        }
      },
      {
        "mark": {
          "type": "rule",
          "size": 3,
          "opacity": 0.8
        },
        "encoding": {
          "y": {
            "aggregate": "mean",
            "field": "times"
          },
          "color": {
            "field": "Tool",
            "type": "nominal"
          }
        }
      }
    ]
  };

  const specs = [boxPlotSpec, scatterPlotSpec, timeSeriesSpec];
  specs.forEach(spec => {
    const chartContainer = document.createElement("div");
    chartsDiv.appendChild(chartContainer);
    vegaEmbed(chartContainer, spec);
  });
};

const main = () => {
  const archSelect = document.getElementById("arch-select");
  const benchmarkSelect = document.getElementById("benchmark-select");
  const miriToggle = document.getElementById("miri-toggle");

  const populateBenchmarks = (architecture) => {
    benchmarkSelect.innerHTML = "";
    const benchmarks = Object.keys(window.benchmarkData[architecture] || {});
    for (const benchmark of benchmarks) {
      const option = document.createElement("option");
      option.value = benchmark;
      option.textContent = benchmark;
      benchmarkSelect.appendChild(option);
    }
  };

  const updateCharts = () => {
    const selectedArch = archSelect.value;
    const selectedBenchmark = benchmarkSelect.value;
    createCharts(selectedArch, selectedBenchmark);
  };

  archSelect.addEventListener("change", () => {
    const selectedArch = archSelect.value;
    populateBenchmarks(selectedArch);
    updateCharts();
  });

  benchmarkSelect.addEventListener("change", updateCharts);

  miriToggle.addEventListener("click", () => {
    showMiri = !showMiri;
    updateCharts();
  });

  // Initial load
  if (window.benchmarkData) {
    
    const initialArch = archSelect.value;
    populateBenchmarks(initialArch);
    updateCharts();
  } else {
    document.getElementById("charts").innerHTML = "<p>Benchmark data not loaded. Please ensure data.js is present.</p>";
  }
};

main();
