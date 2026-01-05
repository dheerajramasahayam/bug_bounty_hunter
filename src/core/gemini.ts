import { GoogleGenerativeAI, GenerativeModel, GenerationConfig } from '@google/generative-ai';
import crypto from 'crypto';
import { getConfig } from '../config/settings.js';
import { logger } from './logger.js';
import { db } from './database.js';

export interface VulnerabilityAnalysis {
    isVulnerable: boolean;
    vulnerabilityType: string;
    severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
    confidence: number;
    description: string;
    evidence: string[];
    exploitability: string;
    impact: string;
    remediation: string;
    cweId?: string;
    cvssScore?: number;
}

export interface ApiSecurityAnalysis {
    issues: {
        type: string;
        severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
        description: string;
        location: string;
        recommendation: string;
    }[];
    overallRisk: 'critical' | 'high' | 'medium' | 'low' | 'minimal';
    summary: string;
}

export interface PayloadSuggestion {
    payloads: {
        payload: string;
        type: string;
        purpose: string;
        likelihood: 'high' | 'medium' | 'low';
    }[];
    context: string;
}

const SECURITY_RESEARCHER_PROMPT = `You are an expert security researcher and bug bounty hunter with deep knowledge of:
- OWASP Top 10 vulnerabilities
- Web application security testing
- API security testing
- Common vulnerability patterns and exploitation techniques
- Bug bounty report writing

Your task is to analyze HTTP requests/responses and code for security vulnerabilities.
Be thorough but avoid false positives. Only report findings you are confident about.
Always provide evidence and clear reproduction steps.

IMPORTANT: Respond ONLY with valid JSON matching the requested schema. No markdown, no explanations outside the JSON.`;

class GeminiService {
    private client: GoogleGenerativeAI | null = null;
    private model: GenerativeModel | null = null;
    private requestCount = 0;
    private lastRequestTime = 0;
    private readonly minRequestInterval = 100; // ms between requests

    initialize(): void {
        const config = getConfig();

        if (!config.gemini.apiKey || config.gemini.apiKey === 'your_gemini_api_key_here') {
            throw new Error('Gemini API key not configured. Please set GEMINI_API_KEY in your .env file.');
        }

        this.client = new GoogleGenerativeAI(config.gemini.apiKey);
        this.model = this.client.getGenerativeModel({
            model: config.gemini.model,
            systemInstruction: SECURITY_RESEARCHER_PROMPT,
        });

        logger.info('Gemini AI initialized', { model: config.gemini.model });
    }

    private getModel(): GenerativeModel {
        if (!this.model) {
            this.initialize();
        }
        return this.model!;
    }

    private async rateLimit(): Promise<void> {
        const now = Date.now();
        const timeSinceLastRequest = now - this.lastRequestTime;

        if (timeSinceLastRequest < this.minRequestInterval) {
            await new Promise(resolve => setTimeout(resolve, this.minRequestInterval - timeSinceLastRequest));
        }

        this.lastRequestTime = Date.now();
        this.requestCount++;
    }

    private async generateContent(prompt: string, config?: GenerationConfig): Promise<string> {
        // Hashing for cache
        const hash = crypto.createHash('sha256').update(prompt).digest('hex');

        // Check cache
        const cached = db.getCachedGeminiResponse(hash);
        if (cached) {
            logger.debug('Gemini cache hit', { hash: hash.substring(0, 8) });
            return cached;
        }

        await this.rateLimit();

        const model = this.getModel();

        try {
            const result = await model.generateContent({
                contents: [{ role: 'user', parts: [{ text: prompt }] }],
                generationConfig: {
                    temperature: 0.1, // Low temperature for consistent, analytical responses
                    topP: 0.8,
                    maxOutputTokens: 4096,
                    responseMimeType: 'application/json',
                    ...config,
                },
            });

            const response = result.response;
            const text = response.text();

            // Save to cache
            db.cacheGeminiResponse(hash, prompt, text);

            logger.debug('Gemini response received', {
                promptLength: prompt.length,
                responseLength: text.length,
                requestCount: this.requestCount
            });

            return text;
        } catch (error) {
            logger.error('Gemini API error', { error: String(error) });
            throw error;
        }
    }

    async analyzeHttpResponse(
        url: string,
        method: string,
        requestHeaders: Record<string, string>,
        requestBody: string | null,
        responseStatus: number,
        responseHeaders: Record<string, string>,
        responseBody: string,
        parameters: string[]
    ): Promise<VulnerabilityAnalysis> {
        const prompt = `Analyze this HTTP request/response for security vulnerabilities:

URL: ${url}
Method: ${method}
Parameters: ${parameters.join(', ') || 'None'}

REQUEST HEADERS:
${JSON.stringify(requestHeaders, null, 2)}

REQUEST BODY:
${requestBody || 'None'}

RESPONSE STATUS: ${responseStatus}

RESPONSE HEADERS:
${JSON.stringify(responseHeaders, null, 2)}

RESPONSE BODY (truncated to 5000 chars):
${responseBody.substring(0, 5000)}

Look for these vulnerability types:
- SQL Injection (error messages, timing anomalies)
- Cross-Site Scripting (XSS) - reflected content
- Insecure Direct Object References (IDOR)
- Information Disclosure (stack traces, version info, internal paths)
- Security Misconfigurations (missing headers, verbose errors)
- Authentication/Authorization issues
- Sensitive data exposure
- Server-Side Request Forgery indicators

Respond with this JSON schema:
{
  "isVulnerable": boolean,
  "vulnerabilityType": "string (e.g., 'SQL Injection', 'XSS', 'Info Disclosure')",
  "severity": "critical|high|medium|low|info",
  "confidence": number (0.0-1.0),
  "description": "string",
  "evidence": ["array of evidence strings"],
  "exploitability": "string describing how it could be exploited",
  "impact": "string describing business impact",
  "remediation": "string with fix recommendations",
  "cweId": "string (optional, e.g., 'CWE-89')",
  "cvssScore": number (optional, 0.0-10.0)
}`;

        const response = await this.generateContent(prompt);

        try {
            return JSON.parse(response) as VulnerabilityAnalysis;
        } catch {
            logger.warn('Failed to parse Gemini response as JSON', { response: response.substring(0, 200) });
            return {
                isVulnerable: false,
                vulnerabilityType: 'Unknown',
                severity: 'info',
                confidence: 0,
                description: 'Failed to analyze response',
                evidence: [],
                exploitability: 'Unknown',
                impact: 'Unknown',
                remediation: 'Manual review required',
            };
        }
    }

    async analyzeApiEndpoint(
        endpoint: string,
        method: string,
        requestSchema: object | null,
        responseSchema: object | null,
        sampleResponse: string,
        authType: string
    ): Promise<ApiSecurityAnalysis> {
        const prompt = `Analyze this API endpoint for security issues:

Endpoint: ${method} ${endpoint}
Authentication: ${authType}

Request Schema:
${requestSchema ? JSON.stringify(requestSchema, null, 2) : 'Not provided'}

Response Schema:
${responseSchema ? JSON.stringify(responseSchema, null, 2) : 'Not provided'}

Sample Response:
${sampleResponse.substring(0, 3000)}

Check for:
- Authentication/Authorization vulnerabilities
- Mass assignment vulnerabilities
- Excessive data exposure
- Rate limiting issues
- Input validation problems
- BOLA/IDOR possibilities
- Injection vulnerabilities in parameters
- Insecure data handling

Respond with this JSON schema:
{
  "issues": [
    {
      "type": "string",
      "severity": "critical|high|medium|low|info",
      "description": "string",
      "location": "string (e.g., 'request body', 'query parameter')",
      "recommendation": "string"
    }
  ],
  "overallRisk": "critical|high|medium|low|minimal",
  "summary": "string"
}`;

        const response = await this.generateContent(prompt);

        try {
            return JSON.parse(response) as ApiSecurityAnalysis;
        } catch {
            return {
                issues: [],
                overallRisk: 'minimal',
                summary: 'Failed to analyze API endpoint',
            };
        }
    }

    async suggestPayloads(
        url: string,
        parameterName: string,
        parameterType: 'query' | 'body' | 'header' | 'path',
        context: string
    ): Promise<PayloadSuggestion> {
        const prompt = `Suggest security testing payloads for this parameter:

URL: ${url}
Parameter: ${parameterName}
Parameter Type: ${parameterType}
Context: ${context}

Generate payloads for testing:
- SQL Injection
- XSS (Cross-Site Scripting)
- Command Injection
- Path Traversal
- Template Injection
- SSRF (if applicable)

Prioritize payloads likely to succeed based on the context.

Respond with this JSON schema:
{
  "payloads": [
    {
      "payload": "string",
      "type": "string (e.g., 'SQLi', 'XSS')",
      "purpose": "string explaining what this tests",
      "likelihood": "high|medium|low"
    }
  ],
  "context": "string explaining overall testing strategy"
}`;

        const response = await this.generateContent(prompt);

        try {
            return JSON.parse(response) as PayloadSuggestion;
        } catch {
            return {
                payloads: [],
                context: 'Failed to generate payloads',
            };
        }
    }

    async generateReport(
        vulnerabilityType: string,
        severity: string,
        url: string,
        evidence: string[],
        description: string,
        impact: string
    ): Promise<string> {
        const prompt = `Generate a professional bug bounty report for this vulnerability:

Type: ${vulnerabilityType}
Severity: ${severity}
Affected URL: ${url}
Evidence: ${evidence.join('\n')}
Description: ${description}
Impact: ${impact}

Write a complete bug bounty report following this structure:
1. Title
2. Severity
3. Vulnerability Type
4. Summary
5. Steps to Reproduce (numbered, detailed)
6. Proof of Concept (if applicable)
7. Impact
8. Remediation Recommendations
9. References (CVE, CWE, OWASP, etc.)

Make it professional, clear, and ready for submission to HackerOne/Bugcrowd.
Use markdown formatting.`;

        const response = await this.generateContent(prompt, { responseMimeType: 'text/plain' });
        return response;
    }

    async classifyVulnerability(
        rawFinding: {
            url: string;
            indicator: string;
            context: string;
        }
    ): Promise<{
        vulnerabilityType: string;
        severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
        confidence: number;
        isFalsePositive: boolean;
        reasoning: string;
    }> {
        const prompt = `Classify this potential vulnerability finding:

URL: ${rawFinding.url}
Indicator: ${rawFinding.indicator}
Context: ${rawFinding.context}

Determine:
1. What type of vulnerability this indicates (if any)
2. The severity level
3. Your confidence in this finding (0.0-1.0)
4. Whether this is likely a false positive

Respond with this JSON schema:
{
  "vulnerabilityType": "string",
  "severity": "critical|high|medium|low|info",
  "confidence": number,
  "isFalsePositive": boolean,
  "reasoning": "string explaining your classification"
}`;

        const response = await this.generateContent(prompt);

        try {
            return JSON.parse(response);
        } catch {
            return {
                vulnerabilityType: 'Unknown',
                severity: 'info',
                confidence: 0,
                isFalsePositive: true,
                reasoning: 'Failed to classify finding',
            };
        }
    }

    async analyzeJavaScript(
        code: string,
        url: string
    ): Promise<{
        findings: {
            type: string;
            severity: string;
            description: string;
            line: string;
        }[];
        sensitiveData: string[];
        apiEndpoints: string[];
    }> {
        const prompt = `Analyze this JavaScript code for security issues:

Source URL: ${url}

Code:
${code.substring(0, 10000)}

Look for:
- Hardcoded secrets (API keys, tokens, passwords)
- DOM-based XSS sinks (innerHTML, document.write, eval)
- Sensitive API endpoints
- Authentication tokens or logic
- Interesting comments
- Debug/development code
- Prototype pollution possibilities

Respond with this JSON schema:
{
  "findings": [
    {
      "type": "string",
      "severity": "critical|high|medium|low|info",
      "description": "string",
      "line": "string (the vulnerable line or snippet)"
    }
  ],
  "sensitiveData": ["array of any sensitive data found"],
  "apiEndpoints": ["array of API endpoints discovered in the code"]
}`;

        const response = await this.generateContent(prompt);

        try {
            return JSON.parse(response);
        } catch {
            return {
                findings: [],
                sensitiveData: [],
                apiEndpoints: [],
            };
        }
    }

    getRequestCount(): number {
        return this.requestCount;
    }
}

// Singleton instance
export const gemini = new GeminiService();
