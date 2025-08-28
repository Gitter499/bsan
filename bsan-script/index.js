let showMiri = false;

const createCharts = (architecture) => {
  const chartsDiv = document.getElementById("charts");
  chartsDiv.innerHTML = ""; // Clear previous charts

  const data = window.benchmarkData[architecture];

  if (!data) {
    chartsDiv.innerHTML = `<p>No data found for architecture: ${architecture}</p>`;
    return;
  }

  const styledBoxPlotSpec = {
    "$schema": "https://vega.github.io/schema/vega-lite/v5.json",
    "title": `Benchmark Execution Time Comparison (${architecture})`,
    "width": 600,
    "height": 400,
    "data": {
      "values": data.results
    },
    "transform": [
      { "flatten": ["times"] },
      {
        "calculate": "{'./target/release/hello_stress': 'native', './hello_stress': 'BSAN', 'cargo +nightly miri run -p programs --bin hello_stress': 'Miri'}[datum.command]",
        "as": "Tool"
      },
      { "filter": showMiri ? "true" : "datum.Tool !== 'Miri'" }
    ],
    "mark": "boxplot",
    "encoding": {
      "x": { "field": "Tool", "type": "nominal" },
      "y": { "field": "times", "type": "quantitative", "scale": { "type": "log" } }
    }
  };

  const styledScatterPlotSpec = {
    "$schema": "https://vega.github.io/schema/vega-lite/v5.json",
    "title": `Benchmark Execution Time Comparison (${architecture})`,
    "width": 600,
    "height": 400,
    "data": {
        "values": data.results
    },
    "transform": [
        { "flatten": ["times"] },
        {
            "calculate": "{'./target/release/hello_stress': 'native', './hello_stress': 'BSAN', 'cargo +nightly miri run -p programs --bin hello_stress': 'Miri'}[datum.command]",
            "as": "Tool"
        },
        { "filter": showMiri ? "true" : "datum.Tool !== 'Miri'" }
    ],
    "mark": "point",
    "encoding": {
        "x": { "field": "times", "type": "quantitative" },
        "y": { "field": "Tool", "type": "nominal" },
        "color": { "field": "Tool", "type": "nominal" }
    }
  };

  const boxPlotContainer = document.createElement("div");
  chartsDiv.appendChild(boxPlotContainer);
  vegaEmbed(boxPlotContainer, styledBoxPlotSpec);

  const scatterPlotContainer = document.createElement("div");
  chartsDiv.appendChild(scatterPlotContainer);
  vegaEmbed(scatterPlotContainer, styledScatterPlotSpec);
};

const main = () => {
  const archSelect = document.getElementById("arch-select");
  const miriToggle = document.getElementById("miri-toggle");

  const updateCharts = () => {
    const selectedArch = archSelect.value;
    createCharts(selectedArch);
  };

  archSelect.addEventListener("change", updateCharts);
  miriToggle.addEventListener("click", () => {
    showMiri = !showMiri;
    updateCharts();
  });

  // Initial load
  if (window.benchmarkData) {
    updateCharts();
  } else {
    document.getElementById("charts").innerHTML = "<p>Benchmark data not loaded. Please ensure data.js is present.</p>";
  }
};

main();
