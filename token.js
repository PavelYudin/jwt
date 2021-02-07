const jwt=require('jsonwebtoken');
module.exports=(function(){
    const secret='Test';
    const nameToken='auth';
    let accessToken=refreshToken=null;
    return {    
                hashRefreshToken:null,
                accessToken:accessToken,
                refreshToken:refreshToken,
                nameToken:nameToken,
                getToken(login){
                    this.accessToken=jwt.sign({ data: login}, secret, { algorithm: "HS512",expiresIn: '1h'});
                    const sign=this.accessToken.split('.')[2];
                    this.refreshToken=jwt.sign({data:sign},secret,{expiresIn:'2h'});
                },
                verification(token){
                    try{
                        const decoded=jwt.verify(token,secret);
                        return true; 
                    }catch(err){
                        return false;
                    }
                }
            
    }
})()