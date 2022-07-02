import express from "express";
import path from "path";
import session from "express-session";
import bcrypt from "bcrypt";
import passport from "passport";
import passportLocal from "passport-local";

const app = express();

app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false
}))

let users=[];

app.use(express.json());
app.use(express.urlencoded({extended:true}));

app.use(passport.initialize());
app.use(passport.session());
passport.use(new passportLocal.Strategy({
    usernameField: "email"
}, async (email, password, done)=>{
    const user = users.find(user => user.email === email);

    if(user === undefined){
        return done(null,null,{message: "Incorrect email"});
    }

    if(await bcrypt.compare(user.password, password)){
        return done(null,user);
    }

    done(null,null,{message: "Incorrect password"});
}));

passport.serializeUser((user,done)=>{
    done(null, user.id);
})
passport.deserializeUser((id, done)=>{
    done(null,users.find(user => user.id === id));
})

app.get("/register", (req, res)=>{
    res.sendFile(path.resolve('views/register.html'));
});

app.post('/register', async(req, res)=>{
    const {name,email,password} = req.body;

    const hashedPwd = await bcrypt.hash(password,10);
    users.push({
        id: `${Date.now()}_${Math.random()}`,
        name,
        email,
        password: hashedPwd
    })
    res.redirect('/login');
})

app.get("/login", (req, res)=>{
    res.sendFile(path.resolve('views/login.html'));
});

app.post("/login", passport.authenticate("local", {
    successRedirect: "/",
    failureRedirect: "/login"
}));

app.get('/',(req,res)=>{
    if(req.isAuthenticated() === false){
        return res.redirect("/login");
    }
    res.send("hi");
})

app.listen(process.env.PORT)