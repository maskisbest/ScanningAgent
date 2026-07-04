(function () {
  function renderChart(el) {
    var raw = el.getAttribute("data-chart") || "{}";
    var data = {};
    try {
      data = JSON.parse(raw);
    } catch (err) {
      data = {};
    }
    var entries = Object.entries(data).filter(function (item) {
      return Number(item[1]) >= 0;
    });
    if (!entries.length) {
      el.innerHTML = '<div class="empty">暂无数据</div>';
      return;
    }
    entries.sort(function (a, b) {
      return Number(b[1]) - Number(a[1]);
    });
    var max = Math.max.apply(
      null,
      entries.map(function (item) {
        return Number(item[1]) || 0;
      })
    );
    if (max <= 0) {
      max = 1;
    }
    el.innerHTML = entries
      .map(function (item) {
        var label = String(item[0]);
        var value = Number(item[1]) || 0;
        var width = Math.max(2, Math.round((value / max) * 100));
        return (
          '<div class="bar-row">' +
          '<div class="bar-label" title="' +
          escapeHtml(label) +
          '">' +
          escapeHtml(label) +
          "</div>" +
          '<div class="bar-track"><div class="bar-fill" style="width:' +
          width +
          '%"></div></div>' +
          '<div class="bar-value">' +
          value +
          "</div>" +
          "</div>"
        );
      })
      .join("");
  }

  function escapeHtml(value) {
    return String(value)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  window.renderCharts = function () {
    document.querySelectorAll(".bar-chart").forEach(renderChart);
  };

  window.bindAssistant = function () {
    var btn = document.getElementById("assistant-btn");
    var output = document.getElementById("assistant-output");
    if (!btn || !output) {
      return;
    }
    btn.addEventListener("click", function () {
      var scanId = btn.getAttribute("data-scan-id");
      btn.disabled = true;
      output.textContent = "正在生成分析...";
      fetch("/api/scan/" + scanId + "/assistant", { method: "POST" })
        .then(function (resp) {
          return resp.json();
        })
        .then(function (data) {
          output.textContent = data.analysis || data.error || "没有返回内容。";
        })
        .catch(function (err) {
          output.textContent = "生成失败：" + err;
        })
        .finally(function () {
          btn.disabled = false;
        });
    });
  };

  window.pollScanIfRunning = function () {
    var panel = document.querySelector("[data-scan-id]");
    if (!panel) {
      return;
    }
    var status = panel.getAttribute("data-status");
    if (status !== "running") {
      return;
    }
    var scanId = panel.getAttribute("data-scan-id");
    var statusEl = document.getElementById("scan-status");
    var timer = setInterval(function () {
      fetch("/api/scan/" + scanId)
        .then(function (resp) {
          return resp.json();
        })
        .then(function (data) {
          if (!data.scan) {
            return;
          }
          if (statusEl) {
            statusEl.textContent = data.scan.status;
          }
          if (data.scan.status !== "running") {
            clearInterval(timer);
            window.location.reload();
          }
        })
        .catch(function () {
          clearInterval(timer);
        });
    }, 2000);
  };
})();
