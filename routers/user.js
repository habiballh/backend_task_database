const express = require("express");
const User = require("../models/user");
const router = express.Router();
const auth = require("../middleware/auth");

// post request
router.post("/user", (req, res) => {
  console.log(req.body);

  const user = new User(req.body);

  user
    .save()
    .then((user) => {
      res.status(200).send(user);
    })
    .catch((e) => {
      res.status(400).send(e);
    });
}); /////////////////////////////////////////////////////////////////////////

//get request

router.get("/user",auth, (req, res) => {
  User.find({})
    .then((user) => {
      res.status(200).send(user);
    })
    .catch((e) => {
      res.status(500).send(e);
    });
});
// get by id
router.get("/user/:id",auth, (req, res) => {
  const _id = req.params.id;
  User.findById(_id)
    .then((user) => {
      if (!user) {
        return res.status(404).send("Unable to find user");
      }
      res.status(200).send(user);
    })
    .catch((e) => {
      res.status(500).send(e);
    });
});
// /////////////////////////////////////////////////////////////////////////
// patch request
router.patch("/user/:id",auth, async (req, res) => {
  try {
    const updates = Object.keys(req.body);
    const _id = req.params.id;
    const user = await User.findById(_id);
    if (!user) {
      return res.status(404).send("No User Fond ");
    }
    updates.forEach((ele) => (user[ele] = req.body[ele]));
    await user.save();
    res.status(200).send(user);
  } catch (e) {
    res.status(400).send(e);
  }
});

// /////////////////////////////////////////////////////////////////
// delete request
router.delete("/user/:id", auth,async (req, res) => {
  try {
    const _id = req.body.id;
    const user = await User.findByIdAndDelelete(_id);
    if (!user) {
      return res.status(404).send("User NOT Fond ");
    }
    res.status(200).sned(user);
  } catch (e) {
    res.status(500).send(e);
  }
});
//////////////////////////////////////////////////////////////////////////////////////////
//login
router.post("/login", async (req, res) => {
  try {
    const user = await User.findByCredentials(
      req.body.email,
      req.body.password
    );
    const token = await user.generateToken();
    res.status(200).send({ user, token });
  } catch (e) {
    res.status(400).send(e.message);
  }
});
//////////////////////////////////////////////////////////////////////////////////////////
// token handling
router.post("/user", async (req, res) => {
  try {
    const user = new User(req.body);
    const token = await user.generateToken();
    await user.save();
    res.status(200).send({ user, token });
  } catch (e) {
    res.status(400).send(e);
  }
});
//////////////////////////////////////////////////////////////////////////////////////////
// profile
router.get("/profile", auth, async (req, res) => {
  res.status(200).send(res.user);
});
//////////////////////////////////////////////////////////////////////////////////////////
// logout
router.delete("/logout", auth, async (req, res) => {
  try {
    console.log(req.user);
    req.user.tokens = req.user.tokens.filter((el) => {
      return el !== req.token;
    });
    await req.user.save();
    res.send();
  } catch (e) {
    res.status(500).send();
  }
});
//////////////////////////////////////////////////////////////////////////////////////////
// logoutall
router.delete("/logoutAll", auth, async (req, res) => {
  try {
    req.user.tokens = [];
    await req.user.save();
    res.send();
  } catch (e) {
    res.status(500).send();
  }
});
//////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////

module.exports = router;
