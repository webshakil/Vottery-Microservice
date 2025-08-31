import { query } from '../config/database.js';
import forge from 'node-forge';
import crypto from 'crypto';

/**
 * Register RSA key pair for a user
 */
export const registerKeys = async (userId) => {
  // Generate RSA key pair
  const keypair = forge.pki.rsa.generateKeyPair(2048);
  const publicKeyPem = forge.pki.publicKeyToPem(keypair.publicKey);
  const privateKeyPem = forge.pki.privateKeyToPem(keypair.privateKey);

  // Encrypt private key (placeholder: base64, can replace with threshold encryption)
  const encryptedPrivateKey = forge.util.encode64(privateKeyPem);

  await query(
    `INSERT INTO vottery_biometric_keys(user_id, public_key, encrypted_private_key, threshold_info)
     VALUES($1, $2, $3, $4)`,
    [userId, publicKeyPem, encryptedPrivateKey, JSON.stringify({ threshold: 'example' })]
  );

  return { publicKeyPem, encryptedPrivateKey };
};

/**
 * Add a security question for a user
 */
export const addSecurityQuestion = async (userId, question, answer) => {
  // Fetch user's public key
  const keyResult = await query(`SELECT public_key FROM vottery_biometric_keys WHERE user_id=$1`, [userId]);
  if (keyResult.rowCount === 0) throw new Error('User keys not found');

  const publicKey = forge.pki.publicKeyFromPem(keyResult.rows[0].public_key);

  // Encrypt answer
  const encryptedAnswer = forge.util.encode64(publicKey.encrypt(answer, 'RSA-OAEP'));

  // Generate SHA-256 signature
  const signature = crypto.createHash('sha256').update(answer).digest('hex');

  // Insert question
  await query(
    `INSERT INTO vottery_security_questions(user_id, question, encrypted_answer, signature)
     VALUES($1, $2, $3, $4)`,
    [userId, question, encryptedAnswer, signature]
  );

  return { question, encryptedAnswer, signature };
};

/**
 * Get security questions (just the questions, not answers)
 */
export const getSecurityQuestions = async (userId) => {
  const result = await query(
    `SELECT id, question FROM vottery_security_questions WHERE user_id=$1`,
    [userId]
  );
  return result.rows;
};

/**
 * Verify security answers
 */
export const verifySecurityAnswers = async (userId, answers) => {
  // Fetch user's private key
  const keyResult = await query(`SELECT encrypted_private_key FROM vottery_biometric_keys WHERE user_id=$1`, [userId]);
  if (keyResult.rowCount === 0) throw new Error('User keys not found');

  const privateKeyPem = forge.util.decode64(keyResult.rows[0].encrypted_private_key);
  const privateKey = forge.pki.privateKeyFromPem(privateKeyPem);

  // Fetch stored questions
  const questionIds = answers.map(a => a.questionId);
  const dbResult = await query(
    `SELECT id, encrypted_answer, signature FROM vottery_security_questions WHERE user_id=$1 AND id = ANY($2)`,
    [userId, questionIds]
  );

  // Verify each answer
  for (const a of answers) {
    const dbQ = dbResult.rows.find(q => q.id === a.questionId);
    if (!dbQ) throw new Error('Invalid question ID');

    // Decrypt stored answer
    const decryptedAnswer = privateKey.decrypt(forge.util.decode64(dbQ.encrypted_answer), 'RSA-OAEP');

    // Compare
    if (decryptedAnswer !== a.answer) throw new Error('Answer mismatch');

    // Verify signature
    const hash = crypto.createHash('sha256').update(decryptedAnswer).digest('hex');
    if (hash !== dbQ.signature) throw new Error('Signature mismatch');
  }

  return true;
};
