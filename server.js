import express from "express";
import mongoose from "mongoose";
import "dotenv/config";
import bcrypt from "bcrypt";
import { nanoid } from "nanoid";
import jwt from "jsonwebtoken";
import cors from "cors";
import admin from "firebase-admin";  // firebase server-side
import serviceAccountKey from "./react-js-fullstack-mern-blog-firebase-adminsdk-ofq61-6bf6e7a8ee.json" assert { type: "json" };  // firebase service account
import { getAuth } from "firebase-admin/auth";
import aws from "aws-sdk";

// Schemas 
import User from "./Schema/User.js";
import Blog from "./Schema/Blog.js";
import Notification from "./Schema/Notification.js";
import Comment from "./Schema/Comment.js";

const app = express();
let PORT = 5000;

// used to authenticate multiple Firebase features, 
// such as Database, Storage and Auth, programmatically via the unified Admin SDK
admin.initializeApp({
    credential: admin.credential.cert(serviceAccountKey)
});

// Email & Password pattern to follow 
let emailRegex = /^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/; // regex for email
let passwordRegex = /^(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{6,20}$/; // regex for password

// Now the server accepts JSON data from frontend
app.use(express.json());

// now the server accepts data from any port
app.use(cors());

// Connect to database 
mongoose.connect(process.env.DB_CONNECTION, {
    autoIndex: true
});

// set up AWS S3 bucket 
const s3 = new aws.S3({
    region: "us-west-2",
    accessKeyId: process.env.AWS_ACCESS_KEY,
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY
});

// generate upload URL to upload our imgs to AWS S3
const generateUploadURL = async () => {
    const date = new Date();
    const imgName = `${nanoid()}-${date.getTime()}.jpeg`;  // store imgs with timestamp

    return await s3.getSignedUrlPromise("putObject", {
        Bucket: "react-js-fullstack-blogging-website",
        Key: imgName,
        Expires: 1000,
        ContentType: "image/jpeg"
    });
};

const verifyJWT = (req, res, next) => {
    const authHeader = req.headers["authorization"];
    const token = authHeader && authHeader.split(" ")[1];

    if(token == null) {
        return res.status(401).json({ error: "No access token" });
    }

    jwt.verify(token, process.env.SECRET_ACCESS_TOKEN, (err, user) => {
        if(err) {
            return res.status(403).json({ error: "Invalid access token" });
        }

        req.user = user.id
        next()
    })
}

// these are the only object data to get/return on the frontend on a request
const formatDatatoSend = (user) => {

    const access_token = jwt.sign({ id: user._id }, process.env.SECRET_ACCESS_TOKEN);

    return {
        access_token,
        profile_img: user.personal_info.profile_img,
        username: user.personal_info.username,
        fullname: user.personal_info.fullname
    }
}

// Using 'async' so this operation waits to do the checking 
// if the username split off from the email is the same
// or already exists 
const generateUsername = async (email) => {
    // use the first part of the email as a username
    let username = email.split("@")[0];

    let isUsernameNotUnique = await User.exists({ "personal_info.username": username }).then((result) => result);

    // add 3 unique strings to the username if it's not unique
    isUsernameNotUnique ? username += nanoid().substring(0, 3) : "";

    return username;
}

// upload URL route 
app.get("/get-upload-url", (req, res) => {
    generateUploadURL().then(url => res.status(200).json({ uploadURL: url }))
    .catch(err => {
        console.log(err.message);
        return res.status(500).json({ error: err.message })
    })
});

app.post("/signup", (req, res) => {
    let { fullname, email, password } = req.body;

    // validate form data from the frontend
    if(fullname.length < 3) {
        return res.status(403).json({ "error": "Full name must be at least 3 letters long" });
    }
    if(!email.length) {
        return res.status(403).json({ "error": "Enter an email" });
    }
    if(!emailRegex.test(email)) {
        return res.status(403).json({ "error": "Email format is invalid" });
    }
    if(!passwordRegex.test(password)) {
        return res.status(403).json({ "error": "Password should be 6 to 20 characters long with a number, 1 lowercase and 1 uppercase letters" });
    }

    // hash the password
    bcrypt.hash(password, 10, async (err, hashed_password) => {

        // use the first part of the email as a username
        let username = await generateUsername(email);  // 'await' - so JS waits for its response 

        // User Object
        let user = new User({
            personal_info: { fullname, email, password: hashed_password, username }
        }); 

        // save to DB
        user.save().then((u) => {
            return res.status(200).json(formatDatatoSend(u));
        }).catch(err => {
            if(err.code == 11000) {
                return res.status(500).json({ "error": "Email already exists" });
            }
            return res.status(500).json({ "error": err.message });
        })

        console.log(hashed_password);
    });

    // return res.status(200).json({ "status": "OK" })
});

app.post("/signin", (req, res) => {
    
    let { email, password } = req.body;

    User.findOne({ "personal_info.email": email })
    .then((user) => {
        if(!user) {
            return res.status(403).json({ "error": "Email not found" });
        }

        // if user is logged in with Google, 
        if(!user.google_auth) {
            // check if the password from sign-up is the same during sign-in
            bcrypt.compare(password, user.personal_info.password, (err, result) => {
                if(err) {
                    return res.status(403).json({ "error": "An error occurred during login, please try again" });
                }

                if(!result) {
                    return res.status(403).json({ "error": "Incorrect password" });
                } else {
                    return res.status(200).json(formatDatatoSend(user));
                }
            })
        } else {
            return res.status(403).json({ "error": "Account was created with Google. So, try logging in with your Google acount" })
        }

        
    }).catch(err => {
        console.log(err.message);
        return res.status(500).json({ "error": err.message });
    })
});

// Google Auth
app.post("/google-auth", async (req, res) => {
    let { access_token } = req.body;

    getAuth()
    .verifyIdToken(access_token)
    .then(async (decodedUser) => {
        
        let { email, name, picture } = decodedUser;
        picture = picture.replace("s96-c", "s384-c");

        let user = await User.findOne({ "personal_info.email": email}).select("personal_info.fullname personal_info.username personal_info.profile_img google_auth").then((u) => {
            return u || null
        })
        .catch(err => {
            return res.status(500).json({ "error": err.message })
        })

        // login
        if(user) {
            if(!user.google_auth) {
                return res.status(403).json({ "error": "This email signed up without Google. Please log in with password to access the account" })
            }
        } // sign up
        else {

            let username = await generateUsername(email);
            user = new User({ 
                personal_info: { fullname: name, email, username },
                google_auth: true
            })

            await user.save().then((u) => {
                user = u;
            })
            .catch(err => {
                return res.status(500).json({ "error": err.message })
            })
        }

        return res.status(200).json(formatDatatoSend(user))
    })
    .catch(err => {
        return res.status(500).json({ "error": "Failed to authenticate you with Google. Try another google account" })
    })
})

app.post("/latest-blogs", (req, res) => {

    let { page } = req.body;

    let maxLimit = 5;

    Blog.find({ draft: false })
    .populate("author", "personal_info.profile_img personal_info.username personal_info.fullname -_id")
    .sort({ "publishedAt": -1 })
    .select("blog_id title des banner activity tags publishedAt -_id")
    .skip((page - 1) * maxLimit)
    .limit(maxLimit)
    .then(blogs => {
        return res.status(200).json({ blogs });
    })
    .catch(err => {
        return res.status(500).json({ error: err.message });
    })

})

app.post("/all-latest-blogs-count", (req, res) => {

    Blog.countDocuments({ draft: false })
    .then(count => {
        return res.status(200).json({ totalDocs: count });
    })
    .catch(err => {
        console.log(err.message);
        return res.status(500).json({ error: err.message })
    })
})

app.get("/trending-blogs", (req, res) => {

    let maxLimit = 5;

    Blog.find({ draft: false })
    .populate("author", "personal_info.profile_img personal_info.username personal_info.fullname -_id")
    .sort({ "activity.total_reads": -1, "activity.total_likes": -1, "publishedAt": -1 }) // descending order
    .select("blog_id title publishedAt -_id")
    .limit(maxLimit)
    .then(blogs => {
        return res.status(200).json({ blogs });
    })
    .catch(err => {
        return res.status(500).json({ error: err.message });
    })
})

// create blog route
// only authenticated users can create blog -> by checking the access token already exists
app.post("/create-blog", verifyJWT, (req, res) => {
    
    let authorId = req.user;

    let { banner, title, content, des, tags, draft, id } = req.body;

    if(!title.length) {
        return res.status(403).json({ error: "You must provide a title" });
    }

    if(!draft) {

        if(!des.length || des.length > 200) {
            return res.status(403).json({ error: "A blog description of 200 characters max is needed before publsihing" });
        }
    
        if(!banner.length) {
            return res.status(403).json({ error: "You need a banner before publsihing" });
        }
    
        if(!content.blocks.length) {
            return res.status(403).json({ error: "There must be some content before publishing" });
        }
    
        if(!tags.length || tags.length > 10) {
            return res.status(403).json({ error: "Some tags are needed before publishing - 10 tags max" });
        }
    }

    // convert tags to lowercase
    tags = tags.map(tag => tag.toLowerCase());

    // create a blogId for the blogs so we don't use the ones from the DB 
    let blog_id = id || title.replace(/[^a-zA-Z0-9]/g, " ").replace(/\s+/g, "-").trim() + nanoid();

    if(id) {

        Blog.findOneAndUpdate({ blog_id }, { title, des, banner, content, tags, draft: draft ? draft : false })
        .then(() => {
            return res.status(200).json({ id: blog_id });
        })
        .catch(err => {
            return res.status(500).json({ error: err.message })
        })

    } else {

        // store blog data in database
        let blog = new Blog({
            title, des, banner, content, tags, author: authorId, blog_id, draft: Boolean(draft)
        });

        blog.save().then(blog => {
            // increment the count of 'total_posts' only if a post is published not saved as draft
            let incrementValue = draft ? 0 : 1;

            User.findOneAndUpdate({ _id: authorId }, { $inc: { "account_info.total_posts" : incrementValue }, $push : { "blogs": blog._id } })
            .then(user => {
                return res.status(200).json({ id: blog.blog_id });
            })
            .catch(err => {
                return res.status(500).json({ error: "Failed to update the count of total posts" });
            })
        })
        .catch(err => {
            return res.status(500).json({ error: err.message });
        })
    }

    
})

app.post("/search-blogs", (req, res) => {

    let { tag, query, page, author, limit, eliminate_same_blog } = req.body;

    let findQuery;

    if(tag) {
        findQuery = { tags: tag, draft: false, blog_id: { $ne: eliminate_same_blog } };
    } else if(query) {
        findQuery = { draft: false, title: new RegExp(query, 'i') }
    } else if(author) {
        findQuery = { author, draft: false }
    }

    // let maxLimit = 3;   only 5 blog posts in a search
    let maxLimit = limit ? limit : 2;

    Blog.find(findQuery)
    .populate("author", "personal_info.profile_img personal_info.username personal_info.fullname -_id")
    .sort({ "publishedAt": -1 })
    .select("blog_id title des banner activity tags publishedAt -_id")
    .skip((page - 1) * maxLimit)
    .limit(maxLimit)
    .then(blogs => {
        return res.status(200).json({ blogs });
    })
    .catch(err => {
        return res.status(500).json({ error: err.message });
    })
})

app.post("/search-blogs-count", (req, res) => {

    let { tag, query, author } = req.body;

    let findQuery;

    if(tag) {
        findQuery = { tags: tag, draft: false };
    } else if(query) {
        findQuery = { draft: false, title: new RegExp(query, 'i') }
    } else if(author) {
        findQuery = { author, draft: false }
    }

    Blog.countDocuments(findQuery)
    .then(count => {
        return res.status(200).json({ totalDocs: count });
    })
    .catch(err => {
        console.log(err.message);
        return res.status(500).json({ error: err.message })
    })

})

app.post("/search-users", (req, res) => {

    let { query } = req.body;

    User.find({ "personal_info.username": new RegExp(query, 'i') })
    .limit(50)
    .select("personal_info.fullname personal_info.username personal_info.profile_img -_id")
    .then(users => {
        return res.status(200).json({ users })
    })
    .catch(err => {
        return res.status(500).json({ error: err.message })
    })
})

app.post("/get-profile", (req, res) => {

    let { username } = req.body;

    User.findOne({ "personal_info.username": username })
    .select("-personal_info.password -google_auth -updatedAt -blogs")
    .then(user => {
        return res.status(200).json(user);
    })
    .catch(err => {
        console.log(err);
        return res.status(500).json({ error: err.message });
    })

})

app.post("/get-blog", (req, res) => {

    let { blog_id, draft, mode } = req.body;

    let incrementVal = mode != "edit" ? 1 : 0;

    Blog.findOneAndUpdate({ blog_id }, { $inc: { "activity.total_reads": incrementVal } })
    .populate("author", "personal_info.fullname personal_info.username personal_info.profile_img")
    .select("title des content banner activity publishedAt blog_id tags")
    .then(blog => {

        User.findOneAndUpdate({ "personal_info.username": blog.author.personal_info.username }, {
            $inc: { "account_info.total_reads": incrementVal }
        })
        .catch(err => {
            return res.status(500).json({ error: err.message })
        })

        if(blog.draft && !draft) {
            return res.status(500).json({ error: "You cannot access draft blogs"});
        }

        return res.status(200).json({ blog });
    })
    .catch(err => {
        return res.status(500).json({ error: err.message });
    })
})

app.post("/like-blog", verifyJWT, (req, res) => {

    let user_id = req.user;

    let { _id, isLikedByUser } = req.body;

    let incrementVal = !isLikedByUser ? 1 : -1;

    Blog.findOneAndUpdate({ _id }, { $inc: { "activity.total_likes": incrementVal } })
    .then(blog => {

        if(isLikedByUser) {

            let like = new Notification({
                type: "like",
                blog: _id,
                notification_for: blog.author,
                user: user_id
            });

            like.save().then(notification => {
                return res.status(200).json({ liked_by_user: true })
            });
        } else {

            Notification.findOneAndDelete({ user: user_id, blog: _id, type: "like" })
            .then(data => {
                return res.status(200).json({ liked_by_user: false })
            })
            .catch(err => {
                return res.status(500).json({ error: err.message });
            })
        }
    })

})

app.post("/isliked-by-user", verifyJWT, (req, res) => {

    let user_id = req.user;

    let { _id } = req.body;

    Notification.exists({ user: user_id, type: "like", blog: _id })
    .then(result => {
        return res.status(200).json({ result});
    })
    .catch(err => {
        return res.status(500).json({ error: err.message });
    })

})

app.post("/add-comment", verifyJWT, (req, res) => {

    let user_id = req.user;

    let { _id, comment, blog_author, replying_to } = req.body;

    if(!comment.length) {
        return res.status(403).json({ error: "Write something to leave a comment..." });
    }

    // creating a comment doc
    let commentObj = {
        blog_id: _id, blog_author, comment, commented_by: user_id,
    };

    if(replying_to) {
        commentObj.parent = replying_to;
        commentObj.isReply = true;
    }

    new Comment(commentObj).save().then(async commentFile => {

        let { comment, commentedAt, children } = commentFile;

        Blog.findOneAndUpdate({ _id }, { $push: { "comments": commentFile._id }, $inc: { "activity.total_comments": 1, "activity.total_parent_comments": replying_to ? 0 : 1 } })
        .then(blog => {
            console.log("New comment created")
        });

        let notificationObj = {
            type: replying_to ? "reply" : "comment",
            blog: _id,
            notification_for: blog_author,
            user: user_id,
            comment: commentFile._id
        }

        if(replying_to) {

            notificationObj.replied_on_comment = replying_to;

            await Comment.findOneAndUpdate({ _id: replying_to }, { $push: { children: commentFile._id } })
            .then(replyingToCommentDoc => { notificationObj.notification_for = replyingToCommentDoc.commented_by })

        }

        new Notification(notificationObj).save().then(notification => console.log("new notification created"));

        return res.status(200).json({
            comment, commentedAt, _id: commentFile._id, user_id, children
        });
    });
}) 

app.post("/get-blog-comments", (req, res) => {

    let { blog_id, skip } = req.body;
    let maxLimit = 5;

    Comment.find({ blog_id, isReply: false })
    .populate("commented_by", "personal_info.fullname personal_info.username personal_info.profile_img")
    .skip(skip)
    .limit(maxLimit)
    .sort({
        "commentedAt": -1
    })
    .then(comment => {
        return res.status(200).json(comment);
    })
    .catch(err => {
        console.log(err.message);
        return res.status(500).json({ error: err.message });
    })
})

app.post("/get-replies", (req, res) => {

    let { _id, skip } = req.body;

    let maxLimit = 5;

    Comment.findOne({ _id })
    .populate({
        path: "children",
        options: {
            limit: maxLimit,
            skip: skip,
            sort: { 'commentedAt': -1 }
        },
        populate: {
            path: 'commented_by',
            select: "personal_info.profile_img personal_info.fullname personal_info.username"
        },
        select: "-blog_id -updatedAt"
    })
    .select("children")
    .then(doc => {
        console.log(doc);
        return res.status(200).json({ replies: doc.children });
    })
    .catch(err => {
        return res.status(500).json({ error: err.message });
    })

})

const deleteComments = ( _id ) => {
    Comment.findOneAndDelete({ _id })
    .then(comment => {

        if(comment.parent){
            Comment.findOneAndUpdate({ _id: comment.parent }, { $pull: { children: _id } })
            .then(data => console.log("parent comment deleted"))
            .catch(err => console.log(err));
        }

        Notification.findOneAndDelete({ comment: _id }).then(notification => console.log("comment notification deleted"));

        Notification.findOneAndUpdate({ reply: _id }, { $unset: { reply: 1 } }).then(notification => console.log("reply notification deleted"));

        Blog.findOneAndUpdate({ _id: comment.blog_id }, { $pull: { comments: _id }, $inc: { "activity.total_comments": -1 }, "activity.total_parent_comments": comment.parent ? 0 : -1 })
        .then(blog => {
            if(comment.children.length){
                comment.children.map(replies => {
                    deleteComments(replies)
                })
            }   
        })

    })
    .catch(err => {
        console.log(err.message);
    })
}

app.post("/delete-comment", verifyJWT, (req, res) => {

    let user_id = req.user;

    let { _id } = req.body;

    Comment.findOne({ _id })
    .then(comment => {

        if( user_id == comment.commented_by || user_id == comment.blog_author ){

            deleteComments(_id);

            return res.status(200).json({ status: 'done' });

        } else{
            return res.status(403).json({ error: "Cannot delete this comment" });
        }

    })

})

app.listen(PORT, () => {
    console.log(`Server is listening on port ${PORT}`);
});
