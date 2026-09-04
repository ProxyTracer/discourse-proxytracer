import Component from "@glimmer/component";
import { modifier } from "ember-modifier";
import loadChartJS from "discourse/lib/load-chart-js";

const renderProxyTracerChart = modifier((element, [stats]) => {
  let chartInstance = null;
  let isCancelled = false;

  async function initOrUpdate() {
    const Chart = await loadChartJS();
    if (isCancelled || !element.isConnected || !Chart) {
      return;
    }

    const safeStats = stats || [];
    const labels = safeStats.map((s) => s.date);
    const requestsData = safeStats.map((s) => s.requests);
    const detectionsData = safeStats.map((s) => s.detections);

    if (chartInstance) {
      chartInstance.data.labels = labels;
      chartInstance.data.datasets[0].data = requestsData;
      chartInstance.data.datasets[1].data = detectionsData;
      chartInstance.update();
      return;
    }

    const ctx = element.getContext("2d");
    if (!ctx) {
      return;
    }

    chartInstance = new Chart(ctx, {
      type: "line",
      data: {
        labels,
        datasets: [
          {
            label: "Total Requests Checked",
            data: requestsData,
            borderColor: "#0088cc",
            backgroundColor: "rgba(0, 136, 204, 0.1)",
            fill: true,
            tension: 0.3,
          },
          {
            label: "Blocked Proxies / VPNs",
            data: detectionsData,
            borderColor: "#e45735",
            backgroundColor: "rgba(228, 87, 53, 0.15)",
            fill: true,
            tension: 0.3,
          },
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        scales: {
          y: {
            beginAtZero: true,
            ticks: {
              precision: 0,
            },
          },
        },
      },
    });
  }

  initOrUpdate();

  return () => {
    isCancelled = true;
    if (chartInstance) {
      try {
        chartInstance.destroy();
      } catch (e) {
        // ignore destruction errors
      }
      chartInstance = null;
    }
  };
});

export default class ProxyTracerChart extends Component {
  <template>
    <div class="proxytracer-chart-container" style="position: relative; height: 350px; width: 100%;" ...attributes>
      <canvas {{renderProxyTracerChart @stats}}></canvas>
    </div>
  </template>
}
