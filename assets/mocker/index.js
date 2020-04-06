const proxy = {
  "POST /begin_registration": (req, res) => {
    console.log(req.body);

    return res.json({publicKey: {
      attestation: "direct",
      authenticatorSelection: {
        requireResidentKey: false,
        userVerification: "preferred"
      },
      challenge: "Gpo2I8bEq3pJm7fzxCuxgCFToxUhYE2Chhg1irZ4Wx8=",
      pubKeyCredParams: [
        {alg: -8, type: "public-key"},
        {alg: -7, type: "public-key"},
        {alg: -35, type: "public-key"},
        {alg: -36, type: "public-key"},
        {alg: -37, type: "public-key"},
        {alg: -38, type: "public-key"},
        {alg: -39, type: "public-key"},
        {alg: -65535, type: "public-key"},
        {alg: -257, type: "public-key"},
        {alg: -258, type: "public-key"},
        {alg: -259, type: "public-key"}
      ],
      rp: {
        id: "localhost",
        name: "Wiwatta Mongkhonchit"
      },
      timeout: 60000,
      user: {
        name: "test@localhost.com",
        displayName: "Tester",
        id: "test"
      }
    }});
  },
  "POST /finish_registration": (req, res) => {
    console.log(req.body);

    return res.json({
      success: true
    });
  }
};

module.exports = proxy;
