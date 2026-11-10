import React from "react";
import { FolderLock, KeyRound, Lock, Network, ChevronRight } from "lucide-react";
import type { ServiceScore } from "../types";

interface CategoryPillarsProps {
  serviceBreakdown: Record<string, ServiceScore>;
  selectedService: string;
  onSelectService: (service: string) => void;
}

export const CategoryPillars: React.FC<CategoryPillarsProps> = ({
  serviceBreakdown,
  selectedService,
  onSelectService,
}) => {
  const categories = [
    {
      id: "s3",
      title: "S3 Public Access",
      desc: "Bucket ACLs, Wildcard Policies & BlockPublicAccess",
      icon: FolderLock,
      stats: serviceBreakdown["s3"] || { total: 0, passed: 0, failed: 0, score: 100 },
    },
    {
      id: "iam",
      title: "Risky IAM Policies",
      desc: "Admin Wildcards (*:*) & Privilege Escalation Vectors",
      icon: KeyRound,
      stats: serviceBreakdown["iam"] || { total: 0, passed: 0, failed: 0, score: 100 },
    },
    {
      id: "encryption",
      title: "Missing Encryption",
      desc: "Storage Encryption on S3, EBS Volumes & RDS Databases",
      icon: Lock,
      stats: serviceBreakdown["encryption"] || { total: 0, passed: 0, failed: 0, score: 100 },
    },
    {
      id: "ec2",
      title: "Exposed Security Groups",
      desc: "Inbound 0.0.0.0/0 on SSH (22), RDP (3389) & DB Ports",
      icon: Network,
      stats: serviceBreakdown["ec2"] || { total: 0, passed: 0, failed: 0, score: 100 },
    },
  ];

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-3">
      {categories.map((cat) => {
        const Icon = cat.icon;
        const isSelected = selectedService === cat.id;
        const score = cat.stats.score;

        const getPillarBadge = (sc: number) => {
          if (sc >= 90) return "text-emerald-400 bg-emerald-950/60 border-emerald-800";
          if (sc >= 60) return "text-yellow-400 bg-yellow-950/60 border-yellow-800";
          return "text-red-400 bg-red-950/60 border-red-800";
        };

        return (
          <button
            key={cat.id}
            onClick={() => onSelectService(isSelected ? "ALL" : cat.id)}
            className={`rounded-2xl border p-4 text-left transition cursor-pointer flex flex-col justify-between ${
              isSelected
                ? "border-blue-500 bg-blue-950/30 shadow-lg shadow-blue-950/40"
                : "border-gray-800 bg-gray-900/80 hover:border-gray-700"
            }`}
          >
            <div>
              <div className="flex items-center justify-between mb-2">
                <div className="p-2 rounded-xl bg-gray-800 text-blue-400 border border-gray-700">
                  <Icon className="h-5 w-5" />
                </div>
                <span
                  className={`text-xs px-2.5 py-0.5 rounded-full font-bold border ${getPillarBadge(
                    score
                  )}`}
                >
                  {score}% Pass
                </span>
              </div>
              <h3 className="text-sm font-bold text-white tracking-tight">{cat.title}</h3>
              <p className="text-xs text-gray-400 mt-1 line-clamp-2">{cat.desc}</p>
            </div>

            <div className="pt-4 border-t border-gray-800/80 mt-4 flex items-center justify-between text-xs text-gray-400">
              <div className="flex space-x-2">
                <span>Pass: <strong className="text-emerald-400">{cat.stats.passed}</strong></span>
                <span>Fail: <strong className="text-red-400">{cat.stats.failed}</strong></span>
              </div>
              <div className="flex items-center text-blue-400 font-medium">
                <span>Filter</span>
                <ChevronRight className="h-3.5 w-3.5 ml-0.5" />
              </div>
            </div>
          </button>
        );
      })}
    </div>
  );
};
