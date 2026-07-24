import React from "react";

interface ScanDashboardProps {
  progress: number;
  stage: string;
  currentFile: string;
  message: string;
  totalFiles: number;
  scannedFiles: number;
  elapsedMs: number;
  etaMs: number;
  scanSpeed: number;
  findingsCount: number;
  status: string;
  targetPath: string;
}

function formatDuration(ms: number): string {
  if (ms <= 0) return "--:--:--";
  const totalSec = Math.floor(ms / 1000);
  const h = Math.floor(totalSec / 3600);
  const m = Math.floor((totalSec % 3600) / 60);
  const s = totalSec % 60;
  if (h > 0) return `${h}h ${m}m ${s}s`;
  if (m > 0) return `${m}m ${s}s`;
  return `${s}s`;
}

function stageIcon(stage: string): string {
  switch (stage) {
    case "discovering": return "🔍";
    case "scanning_files": return "📄";
    case "scanning_dependencies": return "📦";
    case "scanning_native_dependencies": return "🔬";
    case "preparing_toolchain": return "⚙️";
    case "scanning_external": return "🛡️";
    case "completed": return "✅";
    case "failed": return "❌";
    case "paused": return "⏸️";
    default: return "🔄";
  }
}

function stageLabel(stage: string): string {
  switch (stage) {
    case "discovering": return "Discovering Files";
    case "scanning_files": return "Scanning Source Files";
    case "scanning_dependencies": return "Checking Dependencies";
    case "scanning_native_dependencies": return "Analyzing Dependency Authenticity";
    case "preparing_toolchain": return "Preparing Toolchain";
    case "scanning_external": return "Running External Analyzers";
    case "completed": return "Scan Complete";
    case "failed": return "Scan Failed";
    case "paused": return "Scan Paused";
    case "queued": return "Queued";
    default: return stage;
  }
}

function ScanDashboard({
  progress,
  stage,
  currentFile,
  message,
  totalFiles,
  scannedFiles,
  elapsedMs,
  etaMs,
  scanSpeed,
  findingsCount,
  status,
  targetPath,
}: ScanDashboardProps) {
  const isActive = status === "running" || status === "paused";
  const remainingFiles = Math.max(0, totalFiles - scannedFiles);
  const progressBarWidth = Math.min(100, Math.max(0, progress));
  const displayProgress = progressBarWidth.toFixed(1);

  return (
    <div className="scan-dashboard">
      <div className="dashboard-header">
        <h2>{stageIcon(stage)} {stageLabel(stage)}</h2>
        <span className={`status-badge status-${status}`}>{status}</span>
      </div>

      <div className="dashboard-target">
        <span className="target-label">Target:</span>
        <span className="target-path">{targetPath}</span>
      </div>

      <div className="dashboard-progress-bar">
        <div className="progress-track">
          <div
            className="progress-fill"
            style={{ width: `${progressBarWidth}%` }}
          />
        </div>
        <span className="progress-text">{displayProgress}%</span>
      </div>

      {isActive && (
        <div className="dashboard-current-file">
          <span className="file-label">Current File:</span>
          <span className="file-path">{currentFile || "—"}</span>
        </div>
      )}

      <div className="dashboard-message">
        {message}
      </div>

      <div className="dashboard-stats-grid">
        <div className="stat-card">
          <div className="stat-value">{scannedFiles}</div>
          <div className="stat-label">Files Scanned</div>
        </div>
        <div className="stat-card">
          <div className="stat-value">{remainingFiles}</div>
          <div className="stat-label">Files Remaining</div>
        </div>
        <div className="stat-card">
          <div className="stat-value">{totalFiles}</div>
          <div className="stat-label">Total Files</div>
        </div>
        <div className="stat-card">
          <div className="stat-value">{findingsCount}</div>
          <div className="stat-label">Findings</div>
        </div>
        <div className="stat-card">
          <div className="stat-value">{formatDuration(elapsedMs)}</div>
          <div className="stat-label">Elapsed</div>
        </div>
        <div className="stat-card">
          <div className="stat-value">{etaMs > 0 ? formatDuration(etaMs) : "—"}</div>
          <div className="stat-label">ETA</div>
        </div>
        <div className="stat-card">
          <div className="stat-value">{scanSpeed > 0 ? `${scanSpeed.toFixed(1)}/s` : "—"}</div>
          <div className="stat-label">Scan Speed</div>
        </div>
      </div>
    </div>
  );
}

export default ScanDashboard;
