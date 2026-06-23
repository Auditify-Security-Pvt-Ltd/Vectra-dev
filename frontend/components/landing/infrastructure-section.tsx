"use client";

import { useEffect, useState, useRef } from "react";

const capabilities = [
  { title: "Asset Discovery", stat: "Auto-map", desc: "Domains, Subdomains, IPs" },
  { title: "Vulnerability Scan", stat: "100%", desc: "Detection Coverage" },
  { title: "CVE Correlation", stat: "Real-time", desc: "Threat Intelligence" },
  { title: "Cloud Assessment", stat: "3 Clouds", desc: "AWS, Azure, GCP" },
  { title: "Risk Prioritization", stat: "AI-Driven", desc: "Attack Path Analysis" },
  { title: "Reporting", stat: "Auto", desc: "Executive Ready" },
];

export function InfrastructureSection() {
  const [isVisible, setIsVisible] = useState(false);
  const [activeLocation, setActiveLocation] = useState(0);
  const sectionRef = useRef<HTMLElement>(null);

  useEffect(() => {
    const observer = new IntersectionObserver(
      ([entry]) => {
        if (entry.isIntersecting) setIsVisible(true);
      },
      { threshold: 0.1 }
    );

    if (sectionRef.current) observer.observe(sectionRef.current);
    return () => observer.disconnect();
  }, []);

  useEffect(() => {
    const interval = setInterval(() => {
      setActiveLocation((prev) => (prev + 1) % capabilities.length);
    }, 2000);
    return () => clearInterval(interval);
  }, []);

  return (
    <section ref={sectionRef} className="relative py-24 lg:py-32 overflow-hidden">
      <div className="max-w-[1400px] mx-auto px-6 lg:px-12">
        <div className="grid lg:grid-cols-2 gap-16 lg:gap-24 items-center">
          {/* Left: Content */}
          <div
            className={`transition-all duration-700 ${
              isVisible ? "opacity-100 translate-x-0" : "opacity-0 -translate-x-8"
            }`}
          >
            <span className="inline-flex items-center gap-3 text-sm font-mono text-muted-foreground mb-6">
              <span className="w-8 h-px bg-foreground/30" />
              Unified Platform
            </span>
            <h2 className="text-4xl lg:text-6xl font-display tracking-tight mb-8">
              Everything you need
              <br />
              in one platform.
            </h2>
            <p className="text-xl text-muted-foreground leading-relaxed mb-12">
              Discover, scan, analyze, and report on security risks across your entire infrastructure 
              and cloud environments from a single, unified dashboard.
            </p>

            {/* Stats */}
            <div className="grid grid-cols-3 gap-8">
              <div>
                <div className="text-4xl lg:text-5xl font-display mb-2">6</div>
                <div className="text-sm text-muted-foreground">Core Capabilities</div>
              </div>
              <div>
                <div className="text-4xl lg:text-5xl font-display mb-2">AI</div>
                <div className="text-sm text-muted-foreground">Powered Analysis</div>
              </div>
              <div>
                <div className="text-4xl lg:text-5xl font-display mb-2">3x</div>
                <div className="text-sm text-muted-foreground">Faster Reports</div>
              </div>
            </div>
          </div>

          {/* Right: Capabilities grid */}
          <div
            className={`transition-all duration-700 delay-200 ${
              isVisible ? "opacity-100 translate-x-0" : "opacity-0 translate-x-8"
            }`}
          >
            <div className="grid grid-cols-2 gap-6">
              {capabilities.map((capability, index) => (
                <div
                  key={capability.title}
                  className={`border border-foreground/10 px-6 py-6 transition-all duration-300 hover:border-primary/50 ${
                    activeLocation === index ? "bg-foreground/[0.02]" : ""
                  }`}
                >
                  <div className="flex items-center gap-3 mb-4">
                    <span 
                      className={`w-2 h-2 rounded-full transition-colors duration-300 ${
                        activeLocation === index ? "bg-primary" : "bg-foreground/20"
                      }`}
                    />
                    <div className="text-sm font-mono text-muted-foreground">{capability.stat}</div>
                  </div>
                  <div>
                    <div className="font-medium mb-1">{capability.title}</div>
                    <div className="text-sm text-muted-foreground">{capability.desc}</div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
