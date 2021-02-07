const express = require("express");
const bodyParser = require("body-parser");
const bcrypt = require('bcryptjs');
const jwt=require('./token');
const db=require('./db');
const app = express();
const jsonParser = express.json();
const MongoClient = require("mongodb").MongoClient;
const ObjectId = require('mongodb').ObjectID;
const url = "mongodb://localhost:27017/";

function getHash(token){
		const salt = bcrypt.genSaltSync(10);
		const hash = bcrypt.hashSync(token, salt);
		return hash;
}

app.post("/gettoken", jsonParser, function(req, res){
    const mongoClient = new MongoClient(url, { useUnifiedTopology: true });             
    mongoClient.connect(function(err, client){
    	if(err) {res.redirect(301,'/unauthorized');return;}
        const db = client.db("usersdb");
        const collection = db.collection("users");
        jwt.getToken(req.body.login);
        const hash=getHash(jwt.refreshToken);
        collection.findOneAndUpdate({name:req.body.login},{ $set: {hashRefreshToken: hash}},function(err,result){
        	if(err || !result.value){
        		res.redirect(301,'/unauthorized');
        		return;
        	}else{
        		res.status(200).send({accessToken:jwt.accessToken,refreshToken:jwt.refreshToken,id:result.value._id});
        	}
        	client.close();
        });          		        
    }); 
});

app.post("/refreshtoken",jsonParser,function(req,res){
	const {refreshToken,id}=req.body;
	if(refreshToken && id){
		const mongoClient = new MongoClient(url, { useUnifiedTopology: true });             
    	mongoClient.connect(function(err, client){
    		if(err) {res.redirect(301,'/unauthorized');return;}
    		const db = client.db("usersdb");
       		const collection = db.collection("users");	
       		collection.find({'_id':ObjectId(id)}).toArray(function(err,result){
       			if(err){res.redirect(301,'/unauthorized');return;}
       			const hash=result[result.length-1].hashRefreshToken;
       			if(bcrypt.compareSync(refreshToken,hash) && jwt.verification(refreshToken)){
					jwt.getToken(req.body.login);
					const hashToken=getHash(jwt.refreshToken);
					collection.updateOne({'_id':ObjectId(id)},{ $set: {hashRefreshToken: hashToken}},function(err,result){
						if(err){res.redirect(301,'/unauthorized');return;}
						res.status(200).send({accessToken:jwt.accessToken,refreshToken:jwt.refreshToken,id:id});
						client.close();
					});
				}
       			
       		});     		
    	});
	}else{
		res.redirect(301,'/unauthorized');
		return;
	}
});
app.use('/unauthorized',function(req,res){
	res.status(401).send({message:'Unauthorized'});
})

app.use(function(req,res){
	res.status(404).send("Not Found");
})

app.listen(80, function(){
    console.log("Server run...");
});