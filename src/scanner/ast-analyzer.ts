
import parser from '@babel/parser';
import traverse from '@babel/traverse';
import { logger } from '../core/logger.js';

export interface JsAnalysisResult {
    secrets: Array<{
        type: string;
        value: string;
        line: number;
        confidence: 'high' | 'medium' | 'low';
    }>;
    endpoints: Array<{
        method: string;
        path: string;
        line: number;
    }>;
    sinks: Array<{
        type: string;
        value: string;
        line: number;
    }>;
}

export class AdvancedJsAnalyzer {

    analyze(code: string, filename: string = 'unknown.js'): JsAnalysisResult {
        const result: JsAnalysisResult = {
            secrets: [],
            endpoints: [],
            sinks: []
        };

        try {
            const ast = parser.parse(code, {
                sourceType: 'module',
                plugins: ['jsx', 'typescript']
            });

            // We need to strip types/annotations for regular traverse if using TS parser?
            // Actually babel parser handles it.
            // Problem: @babel/traverse is often a CommonJS module which might have import issues in ESM.
            // We'll see.

            // eslint-disable-next-line @typescript-eslint/no-explicit-any
            const visitor: any = {
                StringLiteral(path: any) {
                    const value = path.node.value;

                    // Simple endpoint detection
                    if (value.startsWith('/') || value.startsWith('http')) {
                        // Very naive, but AST helps avoid comments at least
                        if (value.length > 3 && value.length < 100 && !value.includes(' ') && !value.includes('\n')) {
                            result.endpoints.push({
                                method: 'GET', // Assumed
                                path: value,
                                line: path.node.loc?.start.line || 0
                            });
                        }
                    }

                    // Secrets detection (regex on string literals)
                    if (value.length > 16) {
                        if (value.match(/(?:key|token|auth|secret|password|passwd)/i) ||
                            value.match(/eyJ[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+/) // JWT
                        ) {
                            result.secrets.push({
                                type: 'Potential Secret',
                                value: value,
                                line: path.node.loc?.start.line || 0,
                                confidence: value.length > 20 ? 'high' : 'medium'
                            });
                        }
                    }
                },

                CallExpression(path: any) {
                    const callee = path.node.callee;
                    // Detect dangerous sinks: eval(), innerHTML, etc.
                    if (callee.name === 'eval') {
                        result.sinks.push({
                            type: 'Dangerous Sink (eval)',
                            value: 'eval()',
                            line: path.node.loc?.start.line || 0
                        });
                    }

                    // fetch() or axios calls
                    if (callee.name === 'fetch') {
                        const arg = path.node.arguments[0];
                        if (arg && arg.type === 'StringLiteral') {
                            result.endpoints.push({
                                method: 'GET',
                                path: arg.value,
                                line: path.node.loc?.start.line || 0
                            });
                        }
                    }
                }
            };

            // @ts-ignore
            traverse.default(ast, visitor);

        } catch (error) {
            logger.debug(`Failed to parse JS file ${filename}: ${error}`);
        }

        return result;
    }
}

export const advancedJsAnalyzer = new AdvancedJsAnalyzer();
