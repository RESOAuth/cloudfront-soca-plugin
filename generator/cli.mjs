#!/usr/bin/env node
import { documents, ensure, stable, SocaError } from '../src/config.mjs';
import { requestJson } from '../src/network.mjs';
import { validateDiscovery } from '../src/runtime.mjs';
import { packageZip, readDeployment, saveNewKeys } from './package.mjs';

async function main() {
  const [command, config, keys, output, ...extra] = process.argv.slice(2);
  ensure(extra.length === 0, 'Too many arguments');
  if (command === 'init') {
    ensure(config && !keys && !output, 'Usage: init <private-keys.json>');
    await saveNewKeys(config);
    console.log('Created private keys. Keep this file out of Git and reuse it for subsequent builds.');
    return;
  }
  ensure(['build', 'preview', 'check'].includes(command) && config && keys, 'Usage: init <keys> | build <config> <keys> <new.zip> | preview/check <config> <keys>');
  ensure(command === 'build' ? !!output : !output, 'Unexpected or missing output path');
  const deployment = await readDeployment(config, keys, process.env);
  const docs = documents(deployment.config, deployment.public_keys);
  if (command === 'build') {
    console.log(JSON.stringify(await packageZip(deployment, output)));
    console.log('Private deployment ZIP created. Do not publish it as a release or CI artefact.');
    return;
  }
  if (command === 'preview') {
    console.log(JSON.stringify({ revision: deployment.revision, session_ttl_seconds: deployment.config.session_ttl_seconds, ...docs }, null, 2));
    return;
  }
  const [metadata, jwks, discovery] = await Promise.all([
    requestJson(docs.client_id), requestJson(docs.metadata.jwks_uri),
    requestJson(`${deployment.config.issuer.replace(/\/$/, '')}/.well-known/openid-configuration`),
  ]);
  ensure(stable(metadata) === stable(docs.metadata) && stable(jwks) === stable(docs.jwks), 'Published documents differ from this deployment');
  validateDiscovery(discovery, deployment.config);
  console.log(JSON.stringify({ document_check: 'passed', revision: deployment.revision, cimd: discovery.client_id_metadata_document_supported === true ? 'advertised' : 'unconfirmed', real_login: 'not tested' }));
}

main().catch(error => {
  const reason = error instanceof SocaError ? error.message : error.code === 'EEXIST' ? 'Output exists. Use a new path; existing keys and packages are never overwritten.' : 'Check JSON, key files and public HTTPS endpoints.';
  console.error(`SOCA command failed: ${reason}`);
  process.exitCode = 1;
});
