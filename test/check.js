const { run, mark, logMem } = require('micro-bmark');
const secp = require('..');

// run([4, 8, 16], async (windowSize) => {
run(async (windowSize) => {
  const samples = 1000;
  //console.log(`-------\nBenchmarking window=${windowSize} samples=${samples}...`);
  await mark(() => {
    secp.utils.precompute(windowSize);
  });

  logMem();
  console.log();

  // await mark('getPublicKey 1 bit', samples * 10, () => {
  //   secp.getPublicKey('0000000000000000000000000000000000000000000000000000000000000003');
  // });

  // await mark('getPublicKey 256 bit', samples * 10, () => {
  //   secp.getPublicKey('7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffcfcb');
  // });
  const privateKeys = new Array(2500).fill(0).map(() => secp.utils.randomPrivateKey());
  let i = 0;
  await mark('getPublicKey(utils.randomPrivateKey())', 2500, () => {
    secp.getPublicKey(privateKeys[i++]);
  });

  const tweaks = privateKeys.map((pk) => BigInt(`0x${secp.utils.bytesToHex(pk)}`));

  const total = 1000;
  let nRight = 0;
  for (i = 0; i < total; i++) {
    const bpsjP = new secp.BPSJ8(secp.Point.BASE).multiply(tweaks[i]).toHex(true);
    const checkP = secp.Point.BASE.multiply(tweaks[i]).toHex(true);
    if (bpsjP === checkP) {
      nRight++;
    }
  }
  console.log({nRight, total, percent: nRight/total*100});

  i = 0;
  await mark('BPSJ8', 1000, () => {
    new secp.BPSJ8(secp.Point.BASE).multiply(tweaks[i++]);
  });
  i = 0;
  await mark('window', 1000, () => {
    secp.Point.BASE.multiply(tweaks[i++]);
  });
  i = 0;
  await mark('multiplyUnsafe', 1000, () => {
    secp.Point.BASE.multiplyUnsafe(tweaks[i++]);
  });
  const P = secp.Point.fromHex(secp.getPublicKey(privateKeys[0]));
  i = 0;
  await mark('uncached', 1000, () => {
    P.multiply(tweaks[i++]);
  });

  console.log();
  logMem();
});
