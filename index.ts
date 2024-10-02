import { CognitoIdentityProviderClient, AdminInitiateAuthCommand, AuthFlowType } from '@aws-sdk/client-cognito-identity-provider';
import * as dotenv from 'dotenv';
import * as crypto from 'crypto'; 

dotenv.config();

const client = new CognitoIdentityProviderClient({ region: process.env.AWS_REGION });
const clientId = process.env.COGNITO_CLIENT_ID;
const clientSecret = process.env.COGNITO_CLIENT_SECRET;
const userPoolId = process.env.COGNITO_USER_POOL_ID;

export const handler = async (event: any) => {
    const { cpf, password } = JSON.parse(event.body);

    if (!cpf || !password) {
        return {
            statusCode: 400,
            body: JSON.stringify({ message: 'CPF and password are required' }),
        };
    }

    if (!isValidCPF(cpf)) {
        return {
            statusCode: 400,
            body: JSON.stringify({ message: 'Invalid CPF' }),
        };
    }

    try {
        const secretHash = generateSecretHash(cpf, clientId!, clientSecret!);

        const params = {
            AuthFlow: AuthFlowType.ADMIN_NO_SRP_AUTH,
            ClientId: clientId!,
            UserPoolId: userPoolId!,
            AuthParameters: {
                USERNAME: cpf,
                PASSWORD: password,
                SECRET_HASH: secretHash, 
            },
        };

        const command = new AdminInitiateAuthCommand(params);
        const response = await client.send(command);

        return {
            statusCode: 200,
            body: JSON.stringify({
                message: 'Authentication successful',
                token: response.AuthenticationResult?.AccessToken,
            }),
        };
    } catch (error) {
        console.error('Authentication error', error);
        return {
            statusCode: 401,
            body: JSON.stringify({ message: 'Incorrect CPF or password' }),
        };
    }
};

const generateSecretHash = (username: string, clientId: string, clientSecret: string): string => {
    return crypto
        .createHmac('SHA256', clientSecret)
        .update(username + clientId)
        .digest('base64');
}

const isValidCPF = (cpf: string): boolean => {
    cpf = cpf.replace(/[^\d]+/g, '');

    if (cpf.length !== 11 || /^(\d)\1{10}$/.test(cpf)) {
        return false;
    }

    let sum = 0;
    let remainder;

    for (let i = 1; i <= 9; i++) {
        sum += parseInt(cpf.substring(i - 1, i)) * (11 - i);
    }

    remainder = (sum * 10) % 11;
    if (remainder === 10 || remainder === 11) remainder = 0;
    if (remainder !== parseInt(cpf.substring(9, 10))) return false;

    sum = 0;
    for (let i = 1; i <= 10; i++) {
        sum += parseInt(cpf.substring(i - 1, i)) * (12 - i);
    }

    remainder = (sum * 10) % 11;
    if (remainder === 10 || remainder === 11) remainder = 0;
    return remainder === parseInt(cpf.substring(10, 11));
}
