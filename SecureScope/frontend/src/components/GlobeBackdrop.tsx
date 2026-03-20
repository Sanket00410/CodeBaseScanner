import React, { useEffect, useRef } from "react";

type GlobeMode = "landing" | "platform";

const STARS = Array.from({ length: 64 }, (_, index) => {
  const seeded = (index * 9301 + 49297) % 233280;
  const seededTwo = (index * 233 + 1871) % 1000;
  const seededThree = (index * 611 + 73) % 1000;
  return {
    id: index,
    left: `${((seeded / 233280) * 100).toFixed(2)}%`,
    top: `${((seededTwo / 1000) * 100).toFixed(2)}%`,
    size: `${(1 + (seededThree % 3) * 0.9).toFixed(2)}px`,
    delay: `${((index % 11) * 0.27).toFixed(2)}s`,
    duration: `${(3.8 + (index % 7) * 0.6).toFixed(2)}s`,
    opacity: (0.18 + ((seededThree % 10) / 10) * 0.45).toFixed(2),
  };
});

export default function GlobeBackdrop(props: {
  mode: GlobeMode;
}): React.JSX.Element {
  const rootRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    const node = rootRef.current;
    if (!node) {
      return undefined;
    }

    let frame = 0;
    let nextX = 0;
    let nextY = 0;

    const apply = () => {
      frame = 0;
      node.style.setProperty("--globe-mx", nextX.toFixed(3));
      node.style.setProperty("--globe-my", nextY.toFixed(3));
    };

    const updateFromPointer = (clientX: number, clientY: number) => {
      nextX = (clientX / window.innerWidth - 0.5) * 2;
      nextY = (clientY / window.innerHeight - 0.5) * 2;
      if (!frame) {
        frame = window.requestAnimationFrame(apply);
      }
    };

    const handleMove = (event: PointerEvent) => {
      updateFromPointer(event.clientX, event.clientY);
    };

    const handleLeave = () => {
      updateFromPointer(window.innerWidth / 2, window.innerHeight / 2);
    };

    window.addEventListener("pointermove", handleMove);
    window.addEventListener("pointerleave", handleLeave);

    return () => {
      if (frame) {
        window.cancelAnimationFrame(frame);
      }
      window.removeEventListener("pointermove", handleMove);
      window.removeEventListener("pointerleave", handleLeave);
    };
  }, []);

  return (
    <div ref={rootRef} className={`globe-backdrop globe-backdrop-${props.mode}`} aria-hidden="true">
      <div className="globe-backdrop-fade" />
      <div className="globe-stars-layer">
        {STARS.map((star) => (
          <span
            key={star.id}
            className="globe-star"
            style={{
              left: star.left,
              top: star.top,
              width: star.size,
              height: star.size,
              animationDelay: star.delay,
              animationDuration: star.duration,
              opacity: Number(star.opacity),
            }}
          />
        ))}
      </div>
      {props.mode === "landing" ? (
        <div className="earth-scene earth-scene-landing">
          <div className="earth-glow" />
          <div className="earth-hud-ring earth-hud-ring-primary" />
          <div className="earth-hud-ring earth-hud-ring-secondary" />
          <div className="earth-hud-ring earth-hud-ring-tertiary" />
          <div className="earth-reticle" />
          <div className="earth-sphere">
            <div className="earth-texture earth-texture-night" />
            <div className="earth-texture earth-texture-dayglow" />
            <div className="earth-texture earth-texture-clouds" />
            <div className="earth-shade earth-shade-core" />
            <div className="earth-shade earth-shade-rim" />
            <div className="earth-atmosphere" />
          </div>
          <div className="earth-scanline" />
        </div>
      ) : (
        <div className="darkworld-scene darkworld-scene-platform">
          <div className="darkworld-map-frame">
            <div className="darkworld-map" />
          </div>
        </div>
      )}
    </div>
  );
}
