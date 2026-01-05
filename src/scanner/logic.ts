import { gemini } from '../core/gemini.js';
import { logger } from '../core/logger.js';

export interface LogicFlaw {
    type: string; // e.g., 'Price Manipulation', 'Race Condition'
    severity: 'critical' | 'high' | 'medium';
    description: string;
    location: string;
    testSteps: string[];
    likelihood: 'high' | 'medium' | 'low';
}

export class BusinessLogicAnalyzer {

    /**
     * Analyzes a specific workflow context for potential logic flaws.
     * @param workflowType e.g., "Checkout Process", "Password Reset", "User Registration"
     * @param requestDetails Details of the critical request (HTTP method, URL, params)
     * @param businessContext Description of what the feature does
     */
    async analyzeWorkflow(
        workflowType: string,
        requestDetails: string,
        businessContext: string
    ): Promise<LogicFlaw[]> {
        const prompt = `Analyze this business workflow for Logic Vulnerabilities.`; // Note: Logic moved to gemini.ts to centralize AI usage

        try {
            const result = await gemini.analyzeLogic(workflowType, requestDetails, businessContext);
            return result.flaws || [];
        } catch (e) {
            logger.warn('Logic analysis failed', { error: String(e) });
            return [];
        }
    }
}

export const logicAnalyzer = new BusinessLogicAnalyzer();
