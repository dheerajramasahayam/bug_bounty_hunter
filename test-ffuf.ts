
import { ffuf } from './src/tools/ffuf';
import { logger } from './src/core/logger';

async function testFfuf() {
    logger.info('Starting ffuf test...');

    // We can't really test against a real live target without permission and network, 
    // but we can check if it detects availability and tries to run.
    // If we have a local server, that would be ideal.
    // For now, let's just run availability.

    if (await ffuf.isAvailable()) {
        logger.success('ffuf is installed and available');
    } else {
        logger.error('ffuf is NOT installed');
    }
}

testFfuf();
