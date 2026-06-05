/**
 * Import scanner — extracts library names from source code across ecosystems.
 */

const ECOSYSTEM_MAP: Record<string, string> = {
    python: 'python',
    javascript: 'node',
    typescript: 'node',
    javascriptreact: 'node',
    typescriptreact: 'node',
    go: 'go',
    rust: 'rust',
    java: 'java',
    csharp: 'csharp',
    ruby: 'ruby',
    php: 'php',
    kotlin: 'kotlin',
    scala: 'scala',
    swift: 'swift',
    dart: 'dart',
    elixir: 'elixir',
    cpp: 'cpp',
    c: 'cpp',
};

export class ImportScanner {
    detectEcosystem(languageId: string): string | null {
        return ECOSYSTEM_MAP[languageId] || null;
    }

    extractImports(text: string, ecosystem: string): string[] {
        const lines = text.split('\n');
        const imports = new Set<string>();

        for (const line of lines) {
            const libs = this.parseLine(line, ecosystem);
            for (const lib of libs) {
                imports.add(lib);
            }
        }

        return Array.from(imports);
    }

    private parseLine(line: string, ecosystem: string): string[] {
        const trimmed = line.trim();

        switch (ecosystem) {
            case 'python': {
                // import requests / from flask import Flask
                const m1 = trimmed.match(/^import\s+(\w+)/);
                if (m1) return [m1[1]];
                const m2 = trimmed.match(/^from\s+(\w+)/);
                if (m2) return [m2[1]];
                return [];
            }
            case 'node': {
                // require('express') / import x from 'lodash'
                const m1 = trimmed.match(/require\(['"]([^'"]+)['"]\)/);
                if (m1) return [this.npmPackageName(m1[1])];
                const m2 = trimmed.match(/from\s+['"]([^'"]+)['"]/);
                if (m2) return [this.npmPackageName(m2[1])];
                const m3 = trimmed.match(/import\s+['"]([^'"]+)['"]/);
                if (m3) return [this.npmPackageName(m3[1])];
                return [];
            }
            case 'go': {
                // "github.com/gin-gonic/gin"
                const m = trimmed.match(/["']([^"']+\/[^"']+)["']/);
                if (m) return [m[1]];
                return [];
            }
            case 'rust': {
                // use serde::Serialize / extern crate tokio
                const m1 = trimmed.match(/^use\s+(\w+)/);
                if (m1) return [m1[1]];
                const m2 = trimmed.match(/^extern\s+crate\s+(\w+)/);
                if (m2) return [m2[1]];
                return [];
            }
            case 'java':
            case 'kotlin':
            case 'scala': {
                // import java.util.List → skip stdlib
                // import com.google.gson.Gson → gson
                const m = trimmed.match(/^import\s+(?:static\s+)?([a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)+)/);
                if (m) {
                    const parts = m[1].split('.');
                    // Skip java.*, javax.*, kotlin.*, scala.*
                    if (['java', 'javax', 'kotlin', 'scala', 'android'].includes(parts[0])) return [];
                    // Return group:artifact style for Maven
                    return [parts.slice(0, 3).join('.')];
                }
                return [];
            }
            case 'csharp': {
                // using Newtonsoft.Json;
                const m = trimmed.match(/^using\s+([A-Z][a-zA-Z0-9_.]+)/);
                if (m) {
                    // Return top-level namespace as library
                    const parts = m[1].split('.');
                    return [parts.slice(0, Math.min(parts.length, 2)).join('.')];
                }
                return [];
            }
            case 'ruby': {
                // require 'rails' / gem 'sidekiq'
                const m = trimmed.match(/(?:require|gem)\s+['"]([^'"]+)['"]/);
                if (m) return [m[1].split('/')[0]];
                return [];
            }
            case 'php': {
                // use Illuminate\Http\Request;
                const m = trimmed.match(/^use\s+([A-Z][a-zA-Z0-9_\\]+)/);
                if (m) return [m[1].split('\\').slice(0, 2).join('/')];
                return [];
            }
            case 'dart': {
                // import 'package:flutter/material.dart';
                const m = trimmed.match(/import\s+['"]package:([^/]+)/);
                if (m) return [m[1]];
                return [];
            }
            default:
                return [];
        }
    }

    private npmPackageName(specifier: string): string {
        // @scope/package → @scope/package
        // lodash/fp → lodash
        if (specifier.startsWith('@')) {
            const parts = specifier.split('/');
            return parts.slice(0, 2).join('/');
        }
        return specifier.split('/')[0];
    }
}
