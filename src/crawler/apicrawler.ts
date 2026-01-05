import axios from 'axios';
import { logger } from '../core/logger.js';
import { getConfig } from '../config/settings.js';

export interface ApiEndpoint {
    url: string;
    method: string;
    parameters: {
        name: string;
        location: 'query' | 'body' | 'header' | 'path';
        type: string;
        required: boolean;
        example?: string;
    }[];
    requestContentType?: string;
    responseContentType?: string;
    authentication?: string;
    sampleResponse?: string;
}

export interface ApiDiscoveryResult {
    baseUrl: string;
    endpoints: ApiEndpoint[];
    authentication: {
        type: string;
        location: string;
        header?: string;
    }[];
    rateLimiting: boolean;
    documentation?: string;
}

class ApiCrawler {
    private get config() { return getConfig(); }

    async discoverEndpoints(baseUrl: string): Promise<ApiDiscoveryResult> {
        logger.info(`Discovering API endpoints for: ${baseUrl}`);

        const endpoints: ApiEndpoint[] = [];
        const authentication: ApiDiscoveryResult['authentication'] = [];

        // Try common API documentation endpoints
        const docEndpoints = await this.findDocumentation(baseUrl);

        if (docEndpoints.swagger) {
            const swaggerEndpoints = await this.parseSwagger(docEndpoints.swagger);
            endpoints.push(...swaggerEndpoints);
        }

        if (docEndpoints.openapi) {
            const openapiEndpoints = await this.parseOpenAPI(docEndpoints.openapi);
            endpoints.push(...openapiEndpoints);
        }

        // Probe common API paths
        const probedEndpoints = await this.probeCommonPaths(baseUrl);
        endpoints.push(...probedEndpoints);

        // Detect authentication methods
        const authMethods = await this.detectAuthentication(baseUrl);
        authentication.push(...authMethods);

        // Check rate limiting
        const rateLimiting = await this.checkRateLimiting(baseUrl);

        logger.success(`Discovered ${endpoints.length} API endpoints`);

        return {
            baseUrl,
            endpoints,
            authentication,
            rateLimiting,
            documentation: docEndpoints.swagger || docEndpoints.openapi,
        };
    }

    private async findDocumentation(baseUrl: string): Promise<{
        swagger?: string;
        openapi?: string;
        graphql?: string;
    }> {
        const result: { swagger?: string; openapi?: string; graphql?: string } = {};

        const docPaths = [
            '/swagger.json',
            '/swagger/v1/swagger.json',
            '/api/swagger.json',
            '/v1/swagger.json',
            '/v2/swagger.json',
            '/openapi.json',
            '/api/openapi.json',
            '/api-docs',
            '/api-docs.json',
            '/docs/api',
            '/.well-known/openapi.json',
        ];

        for (const path of docPaths) {
            try {
                const url = `${baseUrl}${path}`;
                const response = await axios.get(url, {
                    timeout: 10000,
                    headers: { 'User-Agent': this.config.scanner.userAgent },
                    validateStatus: (status) => status === 200,
                });

                if (response.data?.swagger) {
                    result.swagger = url;
                    logger.info(`Found Swagger documentation: ${url}`);
                } else if (response.data?.openapi) {
                    result.openapi = url;
                    logger.info(`Found OpenAPI documentation: ${url}`);
                }

                if (result.swagger || result.openapi) break;
            } catch {
                // Not found, continue
            }
        }

        // Check for GraphQL
        try {
            const graphqlPaths = ['/graphql', '/api/graphql', '/v1/graphql'];
            for (const path of graphqlPaths) {
                const response = await axios.post(
                    `${baseUrl}${path}`,
                    { query: '{ __schema { types { name } } }' },
                    {
                        timeout: 10000,
                        headers: {
                            'User-Agent': this.config.scanner.userAgent,
                            'Content-Type': 'application/json',
                        },
                        validateStatus: () => true,
                    }
                );

                if (response.data?.data?.__schema) {
                    result.graphql = `${baseUrl}${path}`;
                    logger.info(`Found GraphQL endpoint: ${result.graphql}`);
                    break;
                }
            }
        } catch {
            // GraphQL not found
        }

        return result;
    }

    private async parseSwagger(url: string): Promise<ApiEndpoint[]> {
        try {
            const response = await axios.get(url, {
                timeout: 30000,
                headers: { 'User-Agent': this.config.scanner.userAgent },
            });

            const spec = response.data;
            const endpoints: ApiEndpoint[] = [];
            const basePath = spec.basePath || '';
            const host = spec.host || new URL(url).host;
            const schemes = spec.schemes || ['https'];
            const baseUrl = `${schemes[0]}://${host}${basePath}`;

            if (spec.paths) {
                for (const [path, methods] of Object.entries(spec.paths)) {
                    for (const [method, details] of Object.entries(methods as Record<string, unknown>)) {
                        if (['get', 'post', 'put', 'delete', 'patch'].includes(method)) {
                            const endpoint = this.parseSwaggerEndpoint(
                                baseUrl + path,
                                method.toUpperCase(),
                                details as Record<string, unknown>
                            );
                            endpoints.push(endpoint);
                        }
                    }
                }
            }

            return endpoints;
        } catch (error) {
            logger.warn('Failed to parse Swagger documentation', { error: String(error) });
            return [];
        }
    }

    private parseSwaggerEndpoint(
        url: string,
        method: string,
        details: Record<string, unknown>
    ): ApiEndpoint {
        const parameters: ApiEndpoint['parameters'] = [];

        if (Array.isArray(details.parameters)) {
            for (const param of details.parameters) {
                parameters.push({
                    name: param.name,
                    location: param.in === 'formData' ? 'body' : param.in,
                    type: param.type || 'string',
                    required: param.required || false,
                    example: param.example || param.default,
                });
            }
        }

        return {
            url,
            method,
            parameters,
            requestContentType: Array.isArray(details.consumes) ? details.consumes[0] : undefined,
            responseContentType: Array.isArray(details.produces) ? details.produces[0] : undefined,
        };
    }

    private async parseOpenAPI(url: string): Promise<ApiEndpoint[]> {
        // Similar to parseSwagger but for OpenAPI 3.x
        try {
            const response = await axios.get(url, {
                timeout: 30000,
                headers: { 'User-Agent': this.config.scanner.userAgent },
            });

            const spec = response.data;
            const endpoints: ApiEndpoint[] = [];

            // Get base URL from servers
            const serverUrl = spec.servers?.[0]?.url || new URL(url).origin;

            if (spec.paths) {
                for (const [path, methods] of Object.entries(spec.paths)) {
                    for (const [method, details] of Object.entries(methods as Record<string, unknown>)) {
                        if (['get', 'post', 'put', 'delete', 'patch'].includes(method)) {
                            const endpoint = this.parseOpenAPIEndpoint(
                                serverUrl + path,
                                method.toUpperCase(),
                                details as Record<string, unknown>
                            );
                            endpoints.push(endpoint);
                        }
                    }
                }
            }

            return endpoints;
        } catch (error) {
            logger.warn('Failed to parse OpenAPI documentation', { error: String(error) });
            return [];
        }
    }

    private parseOpenAPIEndpoint(
        url: string,
        method: string,
        details: Record<string, unknown>
    ): ApiEndpoint {
        const parameters: ApiEndpoint['parameters'] = [];

        // Parse path and query parameters
        if (Array.isArray(details.parameters)) {
            for (const param of details.parameters) {
                parameters.push({
                    name: param.name,
                    location: param.in,
                    type: param.schema?.type || 'string',
                    required: param.required || false,
                    example: param.example || param.schema?.example,
                });
            }
        }

        // Parse request body
        const requestBody = details.requestBody as Record<string, unknown> | undefined;
        if (requestBody?.content) {
            const content = requestBody.content as Record<string, unknown>;
            const contentType = Object.keys(content)[0];
            const schema = (content[contentType] as Record<string, unknown>)?.schema as Record<string, unknown>;

            if (schema?.properties) {
                for (const [name, prop] of Object.entries(schema.properties as Record<string, unknown>)) {
                    const propDetails = prop as Record<string, unknown>;
                    parameters.push({
                        name,
                        location: 'body',
                        type: (propDetails.type as string) || 'string',
                        required: Array.isArray(schema.required) && schema.required.includes(name),
                        example: propDetails.example as string,
                    });
                }
            }
        }

        return {
            url,
            method,
            parameters,
        };
    }

    private async probeCommonPaths(baseUrl: string): Promise<ApiEndpoint[]> {
        const commonPaths = [
            { path: '/api/users', methods: ['GET', 'POST'] },
            { path: '/api/user', methods: ['GET'] },
            { path: '/api/me', methods: ['GET'] },
            { path: '/api/profile', methods: ['GET'] },
            { path: '/api/account', methods: ['GET'] },
            { path: '/api/auth/login', methods: ['POST'] },
            { path: '/api/auth/register', methods: ['POST'] },
            { path: '/api/auth/logout', methods: ['POST'] },
            { path: '/api/auth/forgot-password', methods: ['POST'] },
            { path: '/api/auth/reset-password', methods: ['POST'] },
            { path: '/api/products', methods: ['GET'] },
            { path: '/api/items', methods: ['GET'] },
            { path: '/api/orders', methods: ['GET'] },
            { path: '/api/search', methods: ['GET'] },
            { path: '/api/upload', methods: ['POST'] },
            { path: '/api/files', methods: ['GET'] },
            { path: '/api/admin', methods: ['GET'] },
            { path: '/api/config', methods: ['GET'] },
            { path: '/api/settings', methods: ['GET'] },
            { path: '/api/health', methods: ['GET'] },
            { path: '/api/status', methods: ['GET'] },
            { path: '/api/version', methods: ['GET'] },
            { path: '/api/v1', methods: ['GET'] },
            { path: '/api/v2', methods: ['GET'] },
        ];

        const endpoints: ApiEndpoint[] = [];

        for (const { path, methods } of commonPaths) {
            for (const method of methods) {
                try {
                    const url = `${baseUrl}${path}`;
                    const response = await axios({
                        method: method as 'GET' | 'POST',
                        url,
                        timeout: 5000,
                        headers: { 'User-Agent': this.config.scanner.userAgent },
                        validateStatus: () => true,
                        data: method === 'POST' ? {} : undefined,
                    });

                    // Consider it an endpoint if not 404
                    if (response.status !== 404) {
                        endpoints.push({
                            url,
                            method,
                            parameters: [],
                            responseContentType: response.headers['content-type'],
                            sampleResponse: JSON.stringify(response.data).substring(0, 500),
                        });
                        logger.debug(`Found API endpoint: ${method} ${url} (${response.status})`);
                    }
                } catch {
                    // Endpoint not accessible
                }

                // Rate limiting
                await new Promise(resolve => setTimeout(resolve, 50));
            }
        }

        return endpoints;
    }

    private async detectAuthentication(baseUrl: string): Promise<ApiDiscoveryResult['authentication']> {
        const methods: ApiDiscoveryResult['authentication'] = [];

        try {
            // Make a request to detect auth requirements
            const response = await axios.get(`${baseUrl}/api`, {
                timeout: 10000,
                headers: { 'User-Agent': this.config.scanner.userAgent },
                validateStatus: () => true,
            });

            // Check WWW-Authenticate header
            const wwwAuth = response.headers['www-authenticate'];
            if (wwwAuth) {
                if (wwwAuth.includes('Bearer')) {
                    methods.push({ type: 'Bearer Token', location: 'header', header: 'Authorization' });
                }
                if (wwwAuth.includes('Basic')) {
                    methods.push({ type: 'Basic Auth', location: 'header', header: 'Authorization' });
                }
            }

            // Check for API key patterns in response
            const responseText = JSON.stringify(response.data);
            if (/api[_-]?key/i.test(responseText)) {
                methods.push({ type: 'API Key', location: 'header', header: 'X-API-Key' });
            }

        } catch {
            // Ignore errors
        }

        return methods;
    }

    private async checkRateLimiting(baseUrl: string): Promise<boolean> {
        try {
            // Make a few rapid requests
            const requests = Array(5).fill(null).map(() =>
                axios.get(`${baseUrl}/api`, {
                    timeout: 5000,
                    headers: { 'User-Agent': this.config.scanner.userAgent },
                    validateStatus: () => true,
                })
            );

            const responses = await Promise.all(requests);

            // Check for rate limiting indicators
            return responses.some(r =>
                r.status === 429 ||
                r.headers['x-ratelimit-limit'] ||
                r.headers['x-rate-limit-limit'] ||
                r.headers['retry-after']
            );
        } catch {
            return false;
        }
    }
}

export const apiCrawler = new ApiCrawler();
