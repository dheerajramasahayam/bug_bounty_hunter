import axios from 'axios';
import { logger } from '../core/logger.js';
import { db } from '../core/database.js';

export interface CloudAsset {
    type: 's3' | 'azure_blob' | 'gcp_bucket';
    name: string;
    url: string;
    permissions: {
        read: boolean;
        write: boolean;
        list: boolean;
    };
    isVulnerable: boolean;
}

const COMMON_BUCKET_SUFFIXES = [
    'dev', 'prod', 'staging', 'test', 'backup', 'assets', 'static',
    'images', 'public', 'private', 'logs', 'secure', 'internal',
    'admin', 'user', 'app', 'media', 'cdn'
];

export class CloudScanner {

    async scanDomain(domain: string): Promise<CloudAsset[]> {
        const findings: CloudAsset[] = [];
        const baseName = domain.split('.')[0];

        // Generate potential bucket names
        const candidates = this.generateBucketNames(baseName);

        logger.info(`Checking ${candidates.length} potential cloud assets for ${domain}`);

        // Check S3
        for (const name of candidates) {
            const asset = await this.checkS3Bucket(name);
            if (asset) {
                findings.push(asset);
                logger.vulnerability('CLOUD_ASSET', asset.isVulnerable ? 'high' : 'info', asset.url);
            }
        }

        return findings;
    }

    private generateBucketNames(base: string): string[] {
        const names = [base];
        for (const suffix of COMMON_BUCKET_SUFFIXES) {
            names.push(`${base}-${suffix}`);
            names.push(`${base}.${suffix}`);
            names.push(`${base}${suffix}`);
            names.push(`${suffix}-${base}`);
        }
        return names;
    }

    private async checkS3Bucket(name: string): Promise<CloudAsset | null> {
        const url = `https://${name}.s3.amazonaws.com`;

        try {
            // Check existence and permissions via HTTP
            const response = await axios.get(url, { validateStatus: () => true, timeout: 5000 });

            if (response.status === 404) return null; // Does not exist

            const asset: CloudAsset = {
                type: 's3',
                name,
                url,
                permissions: { read: false, write: false, list: false },
                isVulnerable: false
            };

            // Check List (ListingEnabled)
            if (response.status === 200 && response.data.includes('<ListBucketResult>')) {
                asset.permissions.list = true;
                asset.isVulnerable = true;
            }

            // Check Write (PUT) - be careful not to actually write large data
            // We just check if it's NOT 403/401/405
            // Actually, safest is to assume public write if ACL says so, but we can't see ACL 
            // without keys. We can try a benign PUT if valid scope, but for now let's just flag LIST.
            // LIST is usually P3/P4.

            return asset;

        } catch (error) {
            return null;
        }
    }
}

export const cloudScanner = new CloudScanner();
