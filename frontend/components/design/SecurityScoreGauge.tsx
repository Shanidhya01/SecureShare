"use client";

import { PieChart, Pie, Cell } from "recharts";
import { scoreBand, scoreColor } from "@/lib/securityScore";

export default function SecurityScoreGauge({ score, size = 160 }: { score: number; size?: number }) {
  const band = scoreBand(score);
  const color = scoreColor(score);
  const data = [
    { name: "score", value: score },
    { name: "rest", value: 100 - score },
  ];

  return (
    <div className="flex flex-col items-center">
      <div className="relative" style={{ width: size, height: size / 2 + 20 }}>
        <PieChart width={size} height={size}>
          <Pie
            data={data}
            dataKey="value"
            startAngle={180}
            endAngle={0}
            cx="50%"
            cy="100%"
            innerRadius={size * 0.32}
            outerRadius={size * 0.46}
            stroke="none"
            isAnimationActive
          >
            <Cell fill={color} />
            <Cell fill="rgba(100,116,139,0.2)" />
          </Pie>
        </PieChart>
        <div className="absolute inset-x-0 bottom-0 flex flex-col items-center">
          <span className="text-3xl font-black text-foreground">{score}</span>
          <span className="text-[10px] uppercase tracking-wide text-muted-foreground">/ 100</span>
        </div>
      </div>
      <span
        className="mt-2 rounded-full px-3 py-1 text-xs font-bold uppercase tracking-wide ring-1"
        style={{ color, backgroundColor: `${color}1A`, ["--tw-ring-color" as string]: `${color}4D` }}
      >
        {band}
      </span>
    </div>
  );
}
