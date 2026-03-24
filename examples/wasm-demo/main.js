import init, * as wasm from '../../dkls23-core/pkg/dkls23_core.js';

export async function start() {
  await init();
  if (typeof wasm.example_export === 'function') {
    console.log('example_export:', wasm.example_export(42));
  } else {
    console.log('No example_export exported.');
  }
}

start();
