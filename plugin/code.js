/**
 * Send to Canva (2x PNG) - main thread.
 *
 * Primary path: the plugin sends the file key, the node id, and the asset name to the
 * relay. The relay asks the Figma REST API to render the node at scale 2 and gives
 * Canva that render URL. No image bytes pass through the plugin or the relay.
 *
 * Fallback path: if the REST render fails, the plugin exports the node itself and
 * sends the bytes. That path is limited to about 3 MB by the Vercel body cap.
 */

const SETTINGS_KEY = "settings";
const TARGET_WIDTH = 1920;
const TARGET_HEIGHT = 1080;
const ROW_TOLERANCE = 200; // Pixels. Frames within this vertical distance count as one row.
const MAX_NAME_LENGTH = 50; // Canva limit for an asset name.

const EXPORTABLE_TYPES = ["FRAME", "COMPONENT", "COMPONENT_SET", "INSTANCE", "GROUP", "SECTION"];

const DEFAULT_SETTINGS = {
  relayUrl: "",
  pluginKey: "",
  fileKey: "",
  startNumber: 1,
  padWidth: 2,
  separator: " ",
  sizeCheck: true,
};

figma.showUI(__html__, { width: 400, height: 620, themeColors: true });

figma.ui.onmessage = async (message) => {
  try {
    switch (message.type) {
      case "ui-ready": {
        const settings = await loadSettings();
        figma.ui.postMessage({ type: "settings", settings, detectedFileKey: detectFileKey() });
        sendList(settings);
        break;
      }
      case "save-settings": {
        const settings = await saveSettings(message.settings);
        sendList(settings);
        break;
      }
      case "refresh-list": {
        sendList(await loadSettings());
        break;
      }
      case "export-node": {
        await exportNode(message.id);
        break;
      }
      case "run-finished": {
        figma.notify(message.summary || "Done.");
        break;
      }
      default:
        break;
    }
  } catch (error) {
    figma.ui.postMessage({
      type: "plugin-error",
      message: error && error.message ? error.message : String(error),
    });
  }
};

figma.on("selectionchange", async () => {
  sendList(await loadSettings());
});

/* ----------------------------------------------------------------------------
 * Settings
 * ------------------------------------------------------------------------- */

async function loadSettings() {
  const stored = await figma.clientStorage.getAsync(SETTINGS_KEY);
  return Object.assign({}, DEFAULT_SETTINGS, stored || {});
}

async function saveSettings(partial) {
  const settings = Object.assign({}, await loadSettings(), partial || {});
  await figma.clientStorage.setAsync(SETTINGS_KEY, settings);
  return settings;
}

/**
 * figma.fileKey needs the fileKey permission and is not available in every context,
 * so a missing value is normal. The user can paste the key instead.
 */
function detectFileKey() {
  try {
    return typeof figma.fileKey === "string" ? figma.fileKey : "";
  } catch (error) {
    return "";
  }
}

/* ----------------------------------------------------------------------------
 * Frame collection
 * ------------------------------------------------------------------------- */

function collectNodes() {
  const selection = figma.currentPage.selection.filter(isExportable);
  const source = selection.length > 0
    ? selection
    : figma.currentPage.children.filter((node) => node.type === "FRAME");
  return sortForReading(source);
}

function isExportable(node) {
  return EXPORTABLE_TYPES.indexOf(node.type) !== -1;
}

/** Sorts left to right, top to bottom, so numbering follows the canvas layout. */
function sortForReading(nodes) {
  const byY = nodes.slice().sort((a, b) => a.y - b.y);
  const rows = [];

  byY.forEach((node) => {
    const row = rows[rows.length - 1];
    if (row && Math.abs(node.y - row.y) <= ROW_TOLERANCE) {
      row.nodes.push(node);
    } else {
      rows.push({ y: node.y, nodes: [node] });
    }
  });

  const sorted = [];
  rows.forEach((row) => {
    row.nodes.sort((a, b) => a.x - b.x).forEach((node) => sorted.push(node));
  });
  return sorted;
}

function buildAssetName(index, nodeName, settings) {
  const number = String(index).padStart(Number(settings.padWidth) || 2, "0");
  const clean = String(nodeName).replace(/\s+/g, " ").trim();
  const name = `${number}${settings.separator}${clean}`;
  return name.length > MAX_NAME_LENGTH ? name.slice(0, MAX_NAME_LENGTH).trim() : name;
}

function sendList(settings) {
  const nodes = collectNodes();
  const start = Number(settings.startNumber) || 1;
  let counter = start;

  const items = nodes.map((node) => {
    const width = Math.round(node.width);
    const height = Math.round(node.height);
    const correctSize = width === TARGET_WIDTH && height === TARGET_HEIGHT;
    const skipped = Boolean(settings.sizeCheck) && !correctSize;
    const assetName = skipped ? "" : buildAssetName(counter, node.name, settings);

    if (!skipped) counter += 1;

    return {
      id: node.id,
      nodeName: node.name,
      width,
      height,
      outputWidth: width * 2,
      outputHeight: height * 2,
      correctSize,
      skipped,
      assetName,
    };
  });

  figma.ui.postMessage({
    type: "list",
    items,
    usingSelection: figma.currentPage.selection.filter(isExportable).length > 0,
    pageName: figma.currentPage.name,
  });
}

/* ----------------------------------------------------------------------------
 * Export (fallback path only)
 * ------------------------------------------------------------------------- */

async function exportNode(id) {
  const node = await figma.getNodeByIdAsync(id);

  if (!node || !isExportable(node)) {
    figma.ui.postMessage({ type: "export-error", id, message: "The frame no longer exists." });
    return;
  }

  const bytes = await node.exportAsync({
    format: "PNG",
    constraint: { type: "SCALE", value: 2 },
  });

  figma.ui.postMessage({ type: "export-result", id, bytes });
}
