import React, { useEffect, useRef } from "react";

type GlobeMode = "landing" | "platform";

type GlobePoint = {
  lat: number;
  lon: number;
};

type Star = {
  x: number;
  y: number;
  size: number;
  alpha: number;
  drift: number;
};

const COASTLINES: GlobePoint[][] = [
  [
    { lat: 62, lon: -152 },
    { lat: 58, lon: -142 },
    { lat: 52, lon: -132 },
    { lat: 48, lon: -126 },
    { lat: 45, lon: -123 },
    { lat: 39, lon: -122 },
    { lat: 34, lon: -118 },
    { lat: 28, lon: -111 },
    { lat: 23, lon: -106 },
    { lat: 19, lon: -99 },
    { lat: 24, lon: -90 },
    { lat: 30, lon: -83 },
    { lat: 37, lon: -76 },
    { lat: 44, lon: -66 },
    { lat: 51, lon: -59 },
    { lat: 58, lon: -74 },
    { lat: 62, lon: -96 },
    { lat: 62, lon: -120 },
    { lat: 62, lon: -152 },
  ],
  [
    { lat: 12, lon: -79 },
    { lat: 6, lon: -77 },
    { lat: -2, lon: -79 },
    { lat: -10, lon: -78 },
    { lat: -18, lon: -72 },
    { lat: -24, lon: -68 },
    { lat: -31, lon: -63 },
    { lat: -38, lon: -60 },
    { lat: -47, lon: -66 },
    { lat: -52, lon: -72 },
    { lat: -42, lon: -73 },
    { lat: -30, lon: -71 },
    { lat: -18, lon: -67 },
    { lat: -3, lon: -49 },
    { lat: 5, lon: -37 },
    { lat: 10, lon: -45 },
    { lat: 12, lon: -58 },
    { lat: 12, lon: -79 },
  ],
  [
    { lat: 34, lon: -12 },
    { lat: 35, lon: 2 },
    { lat: 36, lon: 17 },
    { lat: 31, lon: 28 },
    { lat: 25, lon: 33 },
    { lat: 14, lon: 36 },
    { lat: 5, lon: 39 },
    { lat: -7, lon: 38 },
    { lat: -18, lon: 34 },
    { lat: -28, lon: 24 },
    { lat: -34, lon: 18 },
    { lat: -30, lon: 10 },
    { lat: -18, lon: 6 },
    { lat: -3, lon: 5 },
    { lat: 10, lon: 2 },
    { lat: 20, lon: -2 },
    { lat: 29, lon: -7 },
    { lat: 34, lon: -12 },
  ],
  [
    { lat: 37, lon: -9 },
    { lat: 44, lon: 0 },
    { lat: 48, lon: 11 },
    { lat: 55, lon: 21 },
    { lat: 58, lon: 33 },
    { lat: 51, lon: 43 },
    { lat: 42, lon: 39 },
    { lat: 37, lon: 27 },
    { lat: 43, lon: 16 },
    { lat: 46, lon: 6 },
    { lat: 42, lon: -2 },
    { lat: 37, lon: -9 },
  ],
  [
    { lat: 34, lon: 36 },
    { lat: 33, lon: 45 },
    { lat: 28, lon: 55 },
    { lat: 25, lon: 66 },
    { lat: 21, lon: 74 },
    { lat: 18, lon: 81 },
    { lat: 15, lon: 90 },
    { lat: 20, lon: 98 },
    { lat: 24, lon: 106 },
    { lat: 31, lon: 118 },
    { lat: 38, lon: 126 },
    { lat: 45, lon: 132 },
    { lat: 49, lon: 121 },
    { lat: 46, lon: 104 },
    { lat: 41, lon: 88 },
    { lat: 38, lon: 72 },
    { lat: 36, lon: 55 },
    { lat: 34, lon: 36 },
  ],
  [
    { lat: -12, lon: 114 },
    { lat: -18, lon: 120 },
    { lat: -25, lon: 132 },
    { lat: -31, lon: 145 },
    { lat: -35, lon: 153 },
    { lat: -29, lon: 153 },
    { lat: -22, lon: 146 },
    { lat: -16, lon: 136 },
    { lat: -13, lon: 126 },
    { lat: -12, lon: 114 },
  ],
  [
    { lat: 59, lon: -44 },
    { lat: 64, lon: -38 },
    { lat: 70, lon: -28 },
    { lat: 74, lon: -21 },
    { lat: 75, lon: -41 },
    { lat: 72, lon: -52 },
    { lat: 66, lon: -55 },
    { lat: 59, lon: -44 },
  ],
];

function interpolateSegment(start: GlobePoint, end: GlobePoint, steps: number): GlobePoint[] {
  const points: GlobePoint[] = [];
  for (let step = 1; step < steps; step += 1) {
    const ratio = step / steps;
    points.push({
      lat: start.lat + (end.lat - start.lat) * ratio,
      lon: start.lon + (end.lon - start.lon) * ratio,
    });
  }
  return points;
}

function densifyCoastlines(paths: GlobePoint[][], steps = 5): GlobePoint[][] {
  return paths.map((path) => {
    const dense: GlobePoint[] = [];
    for (let index = 0; index < path.length; index += 1) {
      const current = path[index];
      const next = path[index + 1];
      dense.push(current);
      if (next) {
        dense.push(...interpolateSegment(current, next, steps));
      }
    }
    return dense;
  });
}

const DENSE_COASTLINES = densifyCoastlines(COASTLINES, 6);

function projectPoint(point: GlobePoint, rotation: number) {
  const lat = (point.lat * Math.PI) / 180;
  const lon = (point.lon * Math.PI) / 180 + rotation;
  const x = Math.cos(lat) * Math.sin(lon);
  const y = Math.sin(lat);
  const z = Math.cos(lat) * Math.cos(lon);
  return { x, y, z };
}

export default function GlobeBackdrop(props: {
  mode: GlobeMode;
}): React.JSX.Element {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) {
      return undefined;
    }
    const context = canvas.getContext("2d");
    if (!context) {
      return undefined;
    }

    let animationFrame = 0;
    let width = 0;
    let height = 0;
    let dpi = 1;
    let rotation = 0;
    let previousTs = 0;
    const stars: Star[] = Array.from({ length: 140 }, () => ({
      x: Math.random(),
      y: Math.random(),
      size: 0.7 + Math.random() * 2.4,
      alpha: 0.1 + Math.random() * 0.45,
      drift: 0.2 + Math.random() * 0.5,
    }));

    const resize = () => {
      const bounds = canvas.getBoundingClientRect();
      dpi = Math.min(2, window.devicePixelRatio || 1);
      width = Math.max(1, Math.floor(bounds.width));
      height = Math.max(1, Math.floor(bounds.height));
      canvas.width = Math.floor(width * dpi);
      canvas.height = Math.floor(height * dpi);
      context.setTransform(dpi, 0, 0, dpi, 0, 0);
    };

    const drawStars = (time: number) => {
      for (const star of stars) {
        const twinkle = 0.65 + Math.sin(time * 0.00055 * star.drift + star.x * 8) * 0.35;
        context.beginPath();
        context.fillStyle = `rgba(207, 236, 255, ${star.alpha * twinkle})`;
        context.arc(star.x * width, star.y * height, star.size, 0, Math.PI * 2);
        context.fill();
      }
    };

    const drawGlobePoints = (
      centerX: number,
      centerY: number,
      radius: number,
      time: number,
    ) => {
      for (let lat = -78; lat <= 78; lat += 8) {
        for (let lon = 0; lon < 360; lon += 4) {
          const projected = projectPoint({ lat, lon }, rotation);
          const x = centerX + projected.x * radius;
          const y = centerY + projected.y * radius * 0.96;
          const alpha =
            projected.z >= 0
              ? 0.16 + projected.z * 0.48
              : 0.06 + Math.max(projected.z + 0.25, 0) * 0.08;
          const size = projected.z >= 0 ? 1.2 + projected.z * 1.35 : 0.9;
          context.beginPath();
          context.fillStyle = `rgba(209, 240, 255, ${alpha})`;
          context.arc(x, y, size, 0, Math.PI * 2);
          context.fill();
        }
      }

      context.lineWidth = 1;
      for (const coastline of DENSE_COASTLINES) {
        const front: Array<{ x: number; y: number; alpha: number }> = [];
        for (const point of coastline) {
          const projected = projectPoint(point, rotation);
          front.push({
            x: centerX + projected.x * radius,
            y: centerY + projected.y * radius * 0.96,
            alpha: projected.z >= 0 ? 0.18 + projected.z * 0.62 : 0.02,
          });
        }
        for (let index = 1; index < front.length; index += 1) {
          const previous = front[index - 1];
          const current = front[index];
          const alpha = Math.max(previous.alpha, current.alpha);
          if (alpha <= 0.03) {
            continue;
          }
          context.strokeStyle = `rgba(222, 244, 255, ${alpha})`;
          context.beginPath();
          context.moveTo(previous.x, previous.y);
          context.lineTo(current.x, current.y);
          context.stroke();
        }
      }

      for (let orbit = 0; orbit < 4; orbit += 1) {
        const orbitRadius = radius + orbit * 24;
        context.strokeStyle = `rgba(84, 160, 224, ${0.14 - orbit * 0.025})`;
        context.beginPath();
        context.ellipse(
          centerX,
          centerY,
          orbitRadius,
          orbitRadius * (0.54 + orbit * 0.03),
          time * 0.00004 + orbit * 0.5,
          0,
          Math.PI * 2,
        );
        context.stroke();
      }
    };

    const draw = (timestamp: number) => {
      if (!previousTs) {
        previousTs = timestamp;
      }
      const delta = Math.min(32, timestamp - previousTs);
      previousTs = timestamp;
      rotation += delta * (props.mode === "landing" ? 0.000085 : 0.00005);

      context.clearRect(0, 0, width, height);
      drawStars(timestamp);

      const drift = Math.sin(timestamp * 0.00018) * 8;
      const centerX = props.mode === "landing" ? width * 0.72 : width * 0.85;
      const centerY = (props.mode === "landing" ? height * 0.53 : height * 0.24) + drift;
      const radius = Math.min(width, height) * (props.mode === "landing" ? 0.41 : 0.28);

      const glow = context.createRadialGradient(centerX, centerY, radius * 0.1, centerX, centerY, radius * 1.22);
      glow.addColorStop(0, "rgba(42, 188, 255, 0.18)");
      glow.addColorStop(0.45, "rgba(23, 117, 180, 0.12)");
      glow.addColorStop(1, "rgba(1, 6, 14, 0)");
      context.fillStyle = glow;
      context.beginPath();
      context.arc(centerX, centerY, radius * 1.22, 0, Math.PI * 2);
      context.fill();

      context.fillStyle = "rgba(2, 8, 16, 0.66)";
      context.beginPath();
      context.arc(centerX, centerY, radius * 0.99, 0, Math.PI * 2);
      context.fill();

      const halo = context.createRadialGradient(centerX, centerY - radius * 0.36, radius * 0.2, centerX, centerY, radius);
      halo.addColorStop(0, "rgba(166, 226, 255, 0.16)");
      halo.addColorStop(0.5, "rgba(18, 72, 108, 0.08)");
      halo.addColorStop(1, "rgba(4, 9, 15, 0)");
      context.fillStyle = halo;
      context.beginPath();
      context.arc(centerX, centerY, radius * 0.98, 0, Math.PI * 2);
      context.fill();

      drawGlobePoints(centerX, centerY, radius, timestamp);

      context.strokeStyle = "rgba(173, 230, 255, 0.34)";
      context.lineWidth = 1.2;
      context.beginPath();
      context.arc(centerX, centerY, radius, 0, Math.PI * 2);
      context.stroke();

      animationFrame = window.requestAnimationFrame(draw);
    };

    resize();
    animationFrame = window.requestAnimationFrame(draw);
    window.addEventListener("resize", resize);

    return () => {
      window.cancelAnimationFrame(animationFrame);
      window.removeEventListener("resize", resize);
    };
  }, [props.mode]);

  return (
    <div className={`globe-backdrop globe-backdrop-${props.mode}`} aria-hidden="true">
      <div className="globe-backdrop-fade" />
      <canvas ref={canvasRef} className="globe-backdrop-canvas" />
    </div>
  );
}
