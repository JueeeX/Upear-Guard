(() => {
  "use strict";

  const tokenStorageKey = "safeharness-admin-ui-token";
  const pages = {
    overview: "安全运行总览",
    agents: "Agent",
    topology: "通信拓扑",
    delegations: "授权委派",
    audit: "审计",
  };
  const state = {
    token: sessionStorage.getItem(tokenStorageKey) || "",
    overview: null,
  };

  const elements = {
    notice: document.getElementById("notice"),
    pageTitle: document.getElementById("page-title"),
    connectionStatus: document.getElementById("connection-status"),
    refreshButton: document.getElementById("refresh-button"),
    connectButton: document.getElementById("connect-button"),
    stateVersion: document.getElementById("state-version"),
    metricAgents: document.getElementById("metric-agents"),
    metricActive: document.getElementById("metric-active"),
    metricQuarantined: document.getElementById("metric-quarantined"),
    metricTopology: document.getElementById("metric-topology"),
    stateDetails: document.getElementById("state-details"),
    agentsBody: document.getElementById("agents-body"),
    topologyList: document.getElementById("topology-list"),
    delegationsBody: document.getElementById("delegations-body"),
    auditFilter: document.getElementById("audit-filter"),
    auditBody: document.getElementById("audit-body"),
    auditEmpty: document.getElementById("audit-empty"),
    auditTable: document.getElementById("audit-table"),
    accessDialog: document.getElementById("access-dialog"),
    accessForm: document.getElementById("access-form"),
    accessToken: document.getElementById("access-token"),
    cancelAccess: document.getElementById("cancel-access"),
  };

  function setNotice(message, isError = false) {
    elements.notice.textContent = message;
    elements.notice.classList.toggle("is-error", isError);
  }

  function setConnection(kind, label) {
    elements.connectionStatus.className = "connection-status is-" + kind;
    elements.connectionStatus.textContent = label;
  }

  function api(path, options = {}) {
    const headers = new Headers(options.headers || {});
    headers.set("Accept", "application/json");
    if (state.token) {
      headers.set("X-SafeHarness-UI-Token", state.token);
    }
    return fetch(path, { ...options, headers }).then(async (response) => {
      let payload;
      try {
        payload = await response.json();
      } catch {
        throw new Error("管理服务返回了无效响应。");
      }
      if (!response.ok || payload.ok === false) {
        throw new Error(payload.error && payload.error.message ? payload.error.message : "管理请求失败。");
      }
      return payload;
    });
  }

  async function refreshOverview() {
    if (!state.token) {
      setConnection("idle", "未连接");
      setNotice("请先配置本次浏览器会话的访问令牌。");
      return;
    }
    elements.refreshButton.disabled = true;
    setConnection("idle", "刷新中");
    try {
      const payload = await api("/api/overview");
      state.overview = payload;
      renderOverview(payload);
      setConnection("ready", "已连接");
      setNotice("控制面状态已刷新。");
      await loadAudit();
    } catch (error) {
      setConnection("error", "连接失败");
      setNotice(error.message, true);
    } finally {
      elements.refreshButton.disabled = false;
    }
  }

  function renderOverview(payload) {
    const snapshot = payload.state || {};
    const agents = Array.isArray(snapshot.agents) ? snapshot.agents : [];
    const topology = Array.isArray(snapshot.topology) ? snapshot.topology : [];
    const quarantined = pairSet(snapshot.quarantined);
    const active = agents.filter((agent) => agent.active && !quarantined.has(pairKey(agent.tenant_id, agent.agent_id)));

    elements.stateVersion.textContent = safeValue(payload.version);
    elements.metricAgents.textContent = String(agents.length);
    elements.metricActive.textContent = String(active.length);
    elements.metricQuarantined.textContent = String(quarantined.size);
    elements.metricTopology.textContent = String(topology.length);
    renderStateDetails(payload);
    renderAgents(agents, quarantined);
    renderTopology(topology);
    renderDelegations(Array.isArray(snapshot.delegations) ? snapshot.delegations : []);
  }

  function renderStateDetails(payload) {
    const values = [
      ["更新时间", formatDate(payload.occurred_at)],
      ["最近操作", safeValue(payload.operation)],
      ["执行主体", safeValue(payload.actor)],
      ["签名指纹", truncate(safeValue(payload.signature), 18)],
    ];
    elements.stateDetails.replaceChildren();
    values.forEach(([term, description]) => {
      const row = document.createElement("div");
      const dt = document.createElement("dt");
      const dd = document.createElement("dd");
      dt.textContent = term;
      dd.textContent = description;
      dd.title = description;
      row.append(dt, dd);
      elements.stateDetails.append(row);
    });
  }

  function renderAgents(agents, quarantined) {
    elements.agentsBody.replaceChildren();
    if (!agents.length) {
      appendEmptyRow(elements.agentsBody, 6, "暂无已注册 Agent。");
      return;
    }
    agents.forEach((agent) => {
      const row = document.createElement("tr");
      appendTextCell(row, agent.tenant_id);
      appendTextCell(row, agent.agent_id);
      appendTagsCell(row, agent.roles);
      const statusCell = document.createElement("td");
      const status = agentStatus(agent, quarantined);
      const chip = document.createElement("span");
      chip.className = "status-chip is-" + status.kind;
      chip.textContent = status.label;
      statusCell.append(chip);
      row.append(statusCell);
      appendTagsCell(row, agent.delegable_capabilities);
      const actionCell = document.createElement("td");
      const action = document.createElement("button");
      action.type = "button";
      action.className = "button-quiet" + (status.kind !== "quarantined" ? " is-danger" : "");
      action.textContent = status.kind === "quarantined" ? "恢复" : "隔离";
      action.disabled = true;
    action.title = "请在 SUMC Console 完成重新认证和一次性审批。";
      actionCell.append(action);
      row.append(actionCell);
      elements.agentsBody.append(row);
    });
  }

  function renderTopology(topology) {
    elements.topologyList.replaceChildren();
    if (!topology.length) {
      elements.topologyList.append(emptyBlock("当前没有显式允许的通信路径。"));
      return;
    }
    topology.forEach((rule) => {
      const card = document.createElement("article");
      card.className = "topology-card";
      const tenant = document.createElement("small");
      tenant.textContent = safeValue(rule.tenant_id);
      const route = document.createElement("div");
      route.className = "topology-route";
      const source = document.createElement("span");
      const arrow = document.createElement("span");
      const target = document.createElement("span");
      source.textContent = safeValue(rule.source_agent_id);
      arrow.className = "route-arrow";
      arrow.textContent = "→";
      target.textContent = safeValue(rule.target_agent_id);
      route.append(source, arrow, target);
      const tags = document.createElement("div");
      tags.className = "tag-list";
      appendTags(tags, rule.allowed_kinds);
      card.append(tenant, route, tags);
      elements.topologyList.append(card);
    });
  }

  function renderDelegations(delegations) {
    elements.delegationsBody.replaceChildren();
    if (!delegations.length) {
      appendEmptyRow(elements.delegationsBody, 6, "暂无有效委派。");
      return;
    }
    delegations.forEach((grant) => {
      const row = document.createElement("tr");
      appendTextCell(row, grant.tenant_id);
      appendTextCell(row, grant.grantor_agent_id);
      appendTextCell(row, grant.grantee_agent_id);
      appendTagsCell(row, grant.capabilities);
      appendTextCell(row, formatDate(grant.expires_at));
      appendTextCell(row, safeValue(grant.max_messages));
      elements.delegationsBody.append(row);
    });
  }

  async function loadAudit() {
    if (!state.token) {
      return;
    }
    const formData = new FormData(elements.auditFilter);
    const params = new URLSearchParams();
    ["tenant_id", "source", "action"].forEach((name) => {
      const value = String(formData.get(name) || "").trim();
      if (value) {
        params.set(name, value);
      }
    });
    params.set("limit", "50");
    try {
      const payload = await api("/api/audit?" + params.toString());
      renderAudit(payload);
    } catch (error) {
      elements.auditTable.hidden = true;
      elements.auditEmpty.hidden = false;
      elements.auditEmpty.textContent = error.message;
    }
  }

  function renderAudit(payload) {
    const records = Array.isArray(payload.records) ? payload.records : [];
    if (!payload.available) {
      elements.auditTable.hidden = true;
      elements.auditEmpty.hidden = false;
      elements.auditEmpty.textContent = "未配置只读 SQLite 审计源。";
      return;
    }
    if (!records.length) {
      elements.auditTable.hidden = true;
      elements.auditEmpty.hidden = false;
      elements.auditEmpty.textContent = "没有匹配的已脱敏审计记录。";
      return;
    }
    elements.auditBody.replaceChildren();
    records.forEach((record) => {
      const row = document.createElement("tr");
      appendTextCell(row, formatDate(record.occurred_at));
      appendTextCell(row, record.source);
      appendTextCell(row, record.action);
      appendTextCell(row, record.outcome);
      appendTextCell(row, record.tenant_id);
      appendTextCell(row, record.agent_id);
      appendTextCell(row, record.reason_code);
      elements.auditBody.append(row);
    });
    elements.auditEmpty.hidden = true;
    elements.auditTable.hidden = false;
  }

  function showPage(name) {
    Object.keys(pages).forEach((page) => {
      document.getElementById("page-" + page).hidden = page !== name;
    });
    document.querySelectorAll(".nav-item").forEach((button) => {
      button.classList.toggle("is-active", button.dataset.page === name);
    });
    elements.pageTitle.textContent = pages[name];
    if (name === "audit") {
      loadAudit();
    }
  }

  function appendTextCell(row, value) {
    const cell = document.createElement("td");
    cell.textContent = safeValue(value);
    row.append(cell);
  }

  function appendTagsCell(row, values) {
    const cell = document.createElement("td");
    const list = document.createElement("div");
    list.className = "tag-list";
    appendTags(list, values);
    cell.append(list);
    row.append(cell);
  }

  function appendTags(container, values) {
    const items = Array.isArray(values) ? values : [];
    if (!items.length) {
      const empty = document.createElement("span");
      empty.textContent = "—";
      empty.className = "tag";
      container.append(empty);
      return;
    }
    items.forEach((value) => {
      const tag = document.createElement("span");
      tag.className = "tag";
      tag.textContent = safeValue(value);
      tag.title = safeValue(value);
      container.append(tag);
    });
  }

  function appendEmptyRow(body, columns, message) {
    const row = document.createElement("tr");
    const cell = document.createElement("td");
    cell.colSpan = columns;
    cell.className = "empty-state";
    cell.textContent = message;
    row.append(cell);
    body.append(row);
  }

  function emptyBlock(message) {
    const block = document.createElement("div");
    block.className = "panel empty-state";
    block.textContent = message;
    return block;
  }

  function pairKey(tenantId, agentId) {
    return String(tenantId) + "\u0000" + String(agentId);
  }

  function pairSet(values) {
    const result = new Set();
    (Array.isArray(values) ? values : []).forEach((pair) => {
      if (Array.isArray(pair) && pair.length === 2) {
        result.add(pairKey(pair[0], pair[1]));
      }
    });
    return result;
  }

  function agentStatus(agent, quarantined) {
    if (quarantined.has(pairKey(agent.tenant_id, agent.agent_id))) {
      return { kind: "quarantined", label: "已隔离" };
    }
    return agent.active
      ? { kind: "active", label: "活动" }
      : { kind: "inactive", label: "已停用" };
  }

  function formatDate(value) {
    if (!value) {
      return "—";
    }
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? safeValue(value) : date.toLocaleString("zh-CN", { hour12: false });
  }

  function truncate(value, maxLength) {
    return value.length > maxLength ? value.slice(0, maxLength - 1) + "…" : value;
  }

  function safeValue(value) {
    return value === undefined || value === null || value === "" ? "—" : String(value);
  }

  document.querySelectorAll(".nav-item").forEach((button) => {
    button.addEventListener("click", () => showPage(button.dataset.page));
  });
  elements.refreshButton.addEventListener("click", refreshOverview);
  elements.connectButton.addEventListener("click", () => {
    elements.accessToken.value = "";
    elements.accessDialog.showModal();
    elements.accessToken.focus();
  });
  elements.cancelAccess.addEventListener("click", () => elements.accessDialog.close());
  elements.accessForm.addEventListener("submit", (event) => {
    event.preventDefault();
    const token = elements.accessToken.value.trim();
    if (!token) {
      return;
    }
    state.token = token;
    sessionStorage.setItem(tokenStorageKey, token);
    elements.accessDialog.close();
    refreshOverview();
  });
  elements.auditFilter.addEventListener("submit", (event) => {
    event.preventDefault();
    loadAudit();
  });

  if (state.token) {
    refreshOverview();
  } else {
    setNotice("请先配置本次浏览器会话的访问令牌。");
    elements.accessDialog.showModal();
  }
})();
