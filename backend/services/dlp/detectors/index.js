/**
 * Registry of all DLP detector modules. Each detector is a small, dependency-free, pure module
 * exporting { id, label, category, severity, detect(text) => string[] } - mirroring the
 * dependency-free pattern already used for magic-byte/risk detection in Phase 4
 * (backend/utils/magicBytes.js, backend/services/riskEngine.js). Adding a new detector is just
 * adding a file here and importing it below; nothing else needs to change.
 */
import * as email from "./email.js";
import * as phone from "./phone.js";
import * as creditCard from "./creditCard.js";
import * as aadhaar from "./aadhaar.js";
import * as pan from "./pan.js";
import * as passport from "./passport.js";
import * as iban from "./iban.js";
import * as swift from "./swift.js";
import * as awsAccessKey from "./awsAccessKey.js";
import * as awsSecretKey from "./awsSecretKey.js";
import * as githubToken from "./githubToken.js";
import * as gitlabToken from "./gitlabToken.js";
import * as googleApiKey from "./googleApiKey.js";
import * as openaiApiKey from "./openaiApiKey.js";
import * as jwtToken from "./jwtToken.js";
import * as pemPrivateKey from "./pemPrivateKey.js";
import * as certificate from "./certificate.js";
import * as passwordAssignment from "./passwordAssignment.js";
import * as envSecret from "./envSecret.js";

export const DETECTORS = [
  email,
  phone,
  creditCard,
  aadhaar,
  pan,
  passport,
  iban,
  swift,
  awsAccessKey,
  awsSecretKey,
  githubToken,
  gitlabToken,
  googleApiKey,
  openaiApiKey,
  jwtToken,
  pemPrivateKey,
  certificate,
  passwordAssignment,
  envSecret
];
