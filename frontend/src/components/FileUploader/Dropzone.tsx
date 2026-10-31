"use client";

import { useCallback, useRef, useState } from "react";
import { AnimatePresence, motion } from "framer-motion";
import { FileArchive, FolderOpen, UploadCloud, X } from "lucide-react";

const ACCEPTED =
  ".py,.js,.jsx,.ts,.tsx,.go,.java,.rb,.php,.rs,.c,.h,.cpp,.cs,.sh,.yaml,.yml,.json,.md,.tf,.tfvars,.sql,.html,.css,.xml,.toml,.ini,.cfg,.conf,.env,.properties,.zip";

interface DropzoneProps {
  onFiles: (files: File[]) => void;
  disabled?: boolean;
}

export function Dropzone({ onFiles, disabled }: DropzoneProps) {
  const [dragging, setDragging] = useState(false);
  const [files, setFiles] = useState<File[]>([]);
  const inputRef = useRef<HTMLInputElement>(null);
  const folderInputRef = useRef<HTMLInputElement>(null);

  const addFiles = useCallback(
    (incoming: FileList | File[] | null) => {
      if (!incoming) return;
      const next = Array.from(incoming).filter((file) => {
        if (file.size > 25 * 1024 * 1024) return false;
        return (
          file.name.endsWith(".zip") ||
          ACCEPTED.split(",").some((ext) => file.name.toLowerCase().endsWith(ext)) ||
          !file.name.includes(".")
        );
      });
      setFiles((current) => {
        const merged = [...current];
        for (const file of next) {
          if (!merged.some((f) => f.name === file.name && f.size === file.size)) {
            merged.push(file);
          }
        }
        return merged;
      });
    },
    [],
  );

  const removeFile = (name: string) => {
    const next = files.filter((f) => f.name !== name);
    setFiles(next);
    onFiles(next);
  };

  const commit = () => onFiles(files);

  return (
    <div className="space-y-4">
      <motion.div
        onDragOver={(event) => {
          event.preventDefault();
          if (!disabled) setDragging(true);
        }}
        onDragLeave={() => setDragging(false)}
        onDrop={(event) => {
          event.preventDefault();
          setDragging(false);
          if (disabled) return;
          addFiles(event.dataTransfer.files);
        }}
        animate={dragging ? { scale: 1.008 } : { scale: 1 }}
        transition={{ duration: 0.2, ease: [0.16, 1, 0.3, 1] }}
        className={`panel relative overflow-hidden border-dashed p-8 text-center transition-colors duration-200 ${
          dragging
            ? "border-emerald-glow/80 shadow-glow-emerald"
            : "border-slate-700"
        }`}
      >
        {/* Neon border trace on hover/drag */}
        <div
          aria-hidden
          className={`pointer-events-none absolute inset-y-0 left-0 w-1/3 bg-gradient-to-r from-transparent via-emerald-glow/25 to-transparent transition-opacity duration-200 ${
            dragging ? "opacity-100" : "opacity-0"
          }`}
          style={{ animation: dragging ? "border-trace 1.6s ease-in-out infinite" : undefined }}
        />

        <div className="flex flex-col items-center gap-3">
          <motion.div
            animate={dragging ? { y: -4, scale: 1.05 } : { y: 0, scale: 1 }}
            transition={{ duration: 0.2, ease: [0.16, 1, 0.3, 1] }}
            className="rounded-2xl border border-slate-700 bg-slate-900/70 p-4"
          >
            <UploadCloud
              className={dragging ? "text-emerald-glow" : "text-slate-500"}
              size={28}
              strokeWidth={1.5}
            />
          </motion.div>

          <div>
            <p className="text-base font-medium text-slate-100">
              Drop source files, a <span className="font-mono text-emerald-dim">.zip</span>{" "}
              archive, or an OpenAPI spec
            </p>
            <p className="mt-1 text-sm text-slate-500">
              Python · JavaScript · TypeScript · Go · Docker · Kubernetes · Terraform ·
              OpenAPI/Swagger
            </p>
          </div>

          <div className="mt-2 flex flex-wrap items-center justify-center gap-3">
            <button
              type="button"
              className="btn-primary"
              disabled={disabled}
              onClick={() => inputRef.current?.click()}
            >
              <UploadCloud size={15} />
              Choose files
            </button>
            <button
              type="button"
              className="btn-ghost"
              disabled={disabled}
              onClick={() => folderInputRef.current?.click()}
            >
              <FolderOpen size={15} />
              Upload folder
            </button>
          </div>

          <input
            ref={inputRef}
            type="file"
            multiple
            accept={ACCEPTED}
            className="hidden"
            onChange={(event) => addFiles(event.target.files)}
          />
          <input
            ref={folderInputRef}
            type="file"
            multiple
            // @ts-expect-error - non-standard but supported in Chromium/WebKit
            webkitdirectory=""
            directory=""
            className="hidden"
            onChange={(event) => addFiles(event.target.files)}
          />
        </div>
      </motion.div>

      <AnimatePresence initial={false}>
        {files.length > 0 && (
          <motion.div
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: "auto" }}
            exit={{ opacity: 0, height: 0 }}
            transition={{ duration: 0.25, ease: [0.16, 1, 0.3, 1] }}
            className="overflow-hidden"
          >
            <ul className="panel-inset divide-y divide-slate-700/50">
              {files.slice(0, 12).map((file) => (
                <li
                  key={`${file.name}-${file.size}`}
                  className="flex items-center justify-between gap-3 px-4 py-2.5"
                >
                  <span className="flex min-w-0 items-center gap-2.5">
                    {file.name.endsWith(".zip") ? (
                      <FileArchive size={14} className="shrink-0 text-amber-glow" />
                    ) : (
                      <span className="size-1.5 shrink-0 rounded-full bg-emerald-dim" />
                    )}
                    <span className="truncate font-mono text-xs text-slate-300">
                      {file.name}
                    </span>
                  </span>
                  <span className="flex shrink-0 items-center gap-3">
                    <span className="font-mono text-2xs text-slate-600">
                      {(file.size / 1024).toFixed(1)} KB
                    </span>
                    <button
                      type="button"
                      aria-label={`Remove ${file.name}`}
                      onClick={() => removeFile(file.name)}
                      className="text-slate-600 transition-colors hover:text-crimson-glow"
                    >
                      <X size={14} />
                    </button>
                  </span>
                </li>
              ))}
              {files.length > 12 && (
                <li className="px-4 py-2 font-mono text-2xs text-slate-600">
                  + {files.length - 12} more file(s)
                </li>
              )}
            </ul>

            <button
              type="button"
              onClick={commit}
              disabled={disabled}
              className="btn-primary mt-4 w-full"
            >
              Start audit on {files.length} file{files.length === 1 ? "" : "s"}
            </button>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}
