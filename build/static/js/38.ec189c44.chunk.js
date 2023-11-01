"use strict";(self.webpackChunkclient=self.webpackChunkclient||[]).push([[38],{4038:function(n,e,r){r.r(e);var t,o,i,s,a,l,c,u=r(4165),d=r(5861),x=r(9439),m=r(168),h=r(2791),p=r(7691),f=r(1889),g=r(6314),Z=r(890),v=r(4518),b=r(4721),w=r(7554),j=r(5747),y=r(8096),k=r(7689),P=(r(4184),r(1243)),C=r(7062),S=r(184),z=(0,p.ZP)(f.ZP)(t||(t=(0,m.Z)(["\n  && {\n    display: flex;\n    align-items: center;\n    font-size: 25px;\n    height: 100vh;\n    ","\n  }\n"])),""),A=(0,p.ZP)(f.ZP)(o||(o=(0,m.Z)(["\n  && {\n    display: flex;\n    justify-content: left;\n    align-items: left;\n    font-size: 25px;\n    height: 100vh;\n    padding: 1rem 2rem 1rem 2rem;\n  }\n"]))),F=(0,p.ZP)(g.Z)(i||(i=(0,m.Z)(["\n  && {\n    display: flex;\n    justify-content: center;\n    align-items: left;\n  }\n"]))),E=(0,p.ZP)(j.Z)(s||(s=(0,m.Z)(['\n  && {\n    margin: 1rem;\n    width: 50vw;\n    inputcolor: "#A0BFE0";\n    border: "1px solid white";\n  }\n  & .MuiOutlinedInput-root {\n    & fieldset {\n      border-color: #7895cb;\n    }\n    &:hover fieldset {\n      border-color: #7895cb;\n    }\n    &.Mui-focused fieldset {\n      border-color: #7895cb;\n    }\n  }\n']))),L=(0,p.ZP)(Z.Z)(a||(a=(0,m.Z)(["\n  color: #ffffff;\n  cursor: pointer;\n  &:visited {\n    color: #ffffff;\n  }\n"]))),T=(0,p.ZP)(v.Z)(l||(l=(0,m.Z)(["\n  && {\n    background-color: transparent;\n    border: 2px solid;\n    width: 7rem;\n    margin-left: 1rem;\n    cursor: pointer;\n    box-shadow: inset 0 0 0 0 #5383ec;\n    -webkit-transition: ease-out 0.4s;\n    -moz-transition: ease-out 0.4s;\n    transition: ease-out 0.4s;\n    &:hover {\n      box-shadow: inset 400px 0 0 0 #5383ec;\n    }\n  }\n"]))),B=(0,p.ZP)(Z.Z)(c||(c=(0,m.Z)(["\n  && {\n    display: flex;\n    justify-content: center;\n    color: white;\n    ","\n    font-weight: 500;\n    text-transform: none;\n  }\n"])),"");e.default=function(){var n=(0,k.s0)(),e=(0,h.useState)(""),r=(0,x.Z)(e,2),t=r[0],o=r[1],i=function(){var n=(0,d.Z)((0,u.Z)().mark((function n(e){var r,t;return(0,u.Z)().wrap((function(n){for(;;)switch(n.prev=n.next){case 0:if(n.prev=0,e.preventDefault(),r={username:e.target.username.value,password:e.target.password.value},t=""!==r.username&&!r.username.includes(" ")&&""!==r.password&&!r.password.includes(" "),document.querySelectorAll("input").forEach((function(n){return n.value=""})),!t){n.next=12;break}return n.next=8,P.Z.post("api/auth/login",r,{withCredentials:!0,credentials:"include"});case 8:n.sent.data?window.location.reload():o("Login failed. Please try a different username or password."),n.next=13;break;case 12:o("Please enter a username and password.");case 13:n.next=18;break;case 15:n.prev=15,n.t0=n.catch(0),console.error(n.t0);case 18:case"end":return n.stop()}}),n,null,[[0,15]])})));return function(e){return n.apply(this,arguments)}}();return(0,S.jsx)(S.Fragment,{children:(0,S.jsxs)(p.f6,{theme:w.Z,children:[(0,S.jsx)(C.Z,{}),(0,S.jsx)(z,{container:!0,divider:(0,S.jsx)(b.Z,{orientation:"vertical",flexItem:!0},"login-3"),children:(0,S.jsx)(A,{item:!0,xs:12,sm:7.5,children:(0,S.jsxs)(F,{children:[(0,S.jsx)(Z.Z,{variant:"h2",sx:{textAlign:"left",paddingBottom:"1rem",fontWeight:700,margin:"1rem",color:"#FFFFFF"},children:"Log In"},"login-6"),(0,S.jsx)("form",{onSubmit:i,children:(0,S.jsxs)(y.Z,{onSubmit:i,children:[(0,S.jsx)(E,{type:"text",label:"Username",variant:"outlined",name:"username",sx:{input:{color:"#A0BFE0"},label:{color:"#A0BFE0"}}},"login-9"),(0,S.jsx)(E,{type:"password",label:"Password",color:"primary",variant:"outlined",name:"password",sx:{input:{color:"#A0BFE0"},label:{color:"#A0BFE0"}}},"login-10"),(0,S.jsx)(T,{variant:"contained",type:"submit",sx:{marginTop:"1rem"},children:(0,S.jsx)(B,{variant:"h6",children:"Log In"},"login-12")},"login-11"),t&&(0,S.jsx)(Z.Z,{sx:{color:"red",textAlign:"left",margin:"1rem 1rem 0rem 1rem",fontWeight:200,fontSize:20},children:t},"login-13"),(0,S.jsxs)(L,{sx:{margin:"1rem 1rem 1rem 1rem",color:"#A0BFE0"},children:["Don't have an account?"," ",(0,S.jsx)("span",{onClick:function(){n("/signup")},style:{textDecoration:"underline",color:"white"},children:"Click Here"},"login-15")]},"login-14")]},"login-8")},"login-7")]},"login-5")},"login-4")},"login-2")]},"login-1")})}},4184:function(n,e,r){var t,o,i,s=r(168),a=r(9439),l=r(2791),c=r(4395),u=r(4554),d=r(4663),x=r(3400),m=r(890),h=r(911),p=r(8008),f=r(1889),g=r(4518),Z=r(5022),v=r(7689),b=r(7691),w=r(5193),j=r(6733),y=r(184),k=["Log In","Sign Up"];e.Z=function(n){var e=l.useState(null),r=(0,a.Z)(e,2),P=r[0],C=r[1],S=(0,v.s0)(),z=(0,w.Z)("(max-width:900px)"),A=function(n){C(null),null!=n.currentTarget.role&&S("/"+n.currentTarget.role)},F=(0,b.ZP)(m.Z)(t||(t=(0,s.Z)(["\n    && {\n      display: flex;\n      justify-content: center;\n      color: white;\n      font-weight: 500;\n    }\n  "]))),E=(0,b.ZP)(g.Z)(o||(o=(0,s.Z)(["\n    && {\n      background-color: transparent;\n      border: 2px solid;\n      cursor: pointer;\n      box-shadow: inset 0 0 0 0 #5383ec;\n      -webkit-transition: ease-out 0.4s;\n      -moz-transition: ease-out 0.4s;\n      transition: ease-out 0.4s;\n      &:hover {\n        box-shadow: inset 400px 0 0 0 #5383ec;\n      }\n    }\n  "]))),L=(0,b.ZP)(g.Z)(i||(i=(0,s.Z)(["\n    && {\n      background-color: transparent;\n      cursor: pointer;\n      box-shadow: inset 0 0 0 0 #5383ec;\n      -webkit-transition: ease-out 0.4s;\n      -moz-transition: ease-out 0.4s;\n      transition: ease-out 0.4s;\n      &:hover {\n        box-shadow: inset 400px 0 0 0 #5383ec;\n      }\n    }\n  "])));return(0,y.jsx)(c.Z,{position:"static",sx:{backgroundColor:"transparent",boxShadow:"none"},children:(0,y.jsx)(f.ZP,{item:!0,xs:11,sx:{margin:"1.5rem 2rem 1rem 2rem",padding:"0 1rem 0 1rem"},children:(0,y.jsxs)(d.Z,{disableGutters:!0,children:[(0,y.jsxs)("div",{style:{display:"flex",flexGrow:1,alignItems:"center"},children:[z?null:(0,y.jsx)("img",{src:j,alt:"Catalyst Logo",style:{width:"4rem",marginRight:"0.2rem"}},"navout-5"),(0,y.jsxs)(m.Z,{variant:"h4",noWrap:!0,component:"a",sx:{mr:2,display:{xs:"none",md:"flex"},fontFamily:"avenir",fontWeight:700,color:"inherit",textDecoration:"none",cursor:"pointer"},onClick:function(){S("/")},children:["P",(0,y.jsx)("span",{style:{fontSize:"1.5rem",alignSelf:"flex-end",margin:"0rem 0.5rem 0.15rem 0.15rem"},children:"ROJECT"},"navout-7"),"C",(0,y.jsx)("span",{style:{fontSize:"1.5rem",alignSelf:"flex-end",margin:"0rem 0.5rem 0.15rem 0.15rem"},children:"ATALYST"})]},"navout-6")]},"navout-4"),(0,y.jsxs)(u.Z,{sx:{display:{xs:"none",md:"flex"},gap:"2rem"},children:[(0,y.jsx)(L,{variant:"contained",onClick:function(){S("/login")},children:(0,y.jsx)(F,{variant:"h6",children:"Log In"},"navout-10")},"navout-9"),(0,y.jsx)(E,{variant:"contained",onClick:function(){S("/signup")},children:(0,y.jsx)(F,{variant:"h6",children:"Sign Up"},"navout-12")},"navout-11")]},"navout-8"),(0,y.jsxs)(u.Z,{sx:{flexGrow:0,display:{xs:"flex",md:"none"}},children:[(0,y.jsx)(x.Z,{size:"large","aria-controls":"menu-appbar","aria-haspopup":"true",onClick:function(n){C(n.currentTarget)},color:"inherit",children:(0,y.jsx)(p.Z,{})},"navout-14"),(0,y.jsx)(h.Z,{id:"menu-appbar",anchorEl:P,anchorOrigin:{vertical:"bottom",horizontal:"left"},keepMounted:!0,transformOrigin:{vertical:"top",horizontal:"left"},open:Boolean(P),onClose:A,sx:{display:{xs:"block"}},children:k.map((function(n){return(0,y.jsx)(Z.Z,{onClick:A,role:n.replaceAll(" ","").toLowerCase(),children:(0,y.jsx)(m.Z,{textAlign:"center",children:n})},n)}))},"navout-15")]},"navout-13")]},"navout-3")},"navout-2")},"navout-1")}},7062:function(n,e,r){var t,o,i,s=r(168),a=r(9439),l=r(2791),c=r(4395),u=r(4663),d=r(890),x=r(1889),m=r(4518),h=r(7689),p=r(7691),f=r(5193),g=r(6733),Z=r(184);e.Z=function(n){var e=l.useState(null),r=(0,a.Z)(e,2),v=(r[0],r[1],(0,h.s0)()),b=(0,f.Z)("(max-width:900px)");return(0,p.ZP)(d.Z)(t||(t=(0,s.Z)(["\n    && {\n      display: flex;\n      justify-content: center;\n      color: white;\n      font-weight: 500;\n    }\n  "]))),(0,p.ZP)(m.Z)(o||(o=(0,s.Z)(["\n    && {\n      background-color: transparent;\n      border: 2px solid;\n      cursor: pointer;\n      box-shadow: inset 0 0 0 0 #5383ec;\n      -webkit-transition: ease-out 0.4s;\n      -moz-transition: ease-out 0.4s;\n      transition: ease-out 0.4s;\n      &:hover {\n        box-shadow: inset 400px 0 0 0 #5383ec;\n      }\n    }\n  "]))),(0,p.ZP)(m.Z)(i||(i=(0,s.Z)(["\n    && {\n      background-color: transparent;\n      cursor: pointer;\n      box-shadow: inset 0 0 0 0 #5383ec;\n      -webkit-transition: ease-out 0.4s;\n      -moz-transition: ease-out 0.4s;\n      transition: ease-out 0.4s;\n      &:hover {\n        box-shadow: inset 400px 0 0 0 #5383ec;\n      }\n    }\n  "]))),(0,Z.jsx)(c.Z,{position:"static",sx:{backgroundColor:"transparent",boxShadow:"none"},children:(0,Z.jsx)(x.ZP,{item:!0,xs:11,sx:{margin:"1rem 2rem 0rem 2rem"},children:(0,Z.jsx)(u.Z,{disableGutters:!0,children:(0,Z.jsxs)("div",{style:{display:"flex",flexGrow:1,alignItems:"center"},children:[b?null:(0,Z.jsx)("img",{src:g,alt:"Catalyst Logo",style:{width:"4rem",marginRight:"0.2rem"}},"navout-5"),(0,Z.jsxs)(d.Z,{variant:"h4",noWrap:!0,component:"a",sx:{mr:2,display:{xs:"none",md:"flex"},fontFamily:"avenir",fontWeight:700,color:"inherit",textDecoration:"none",cursor:"pointer"},onClick:function(){v("/")},children:["P",(0,Z.jsx)("span",{style:{fontSize:"1.5rem",alignSelf:"flex-end",margin:"0rem 0.5rem 0.15rem 0.15rem"},children:"ROJECT"},"navout-7"),"C",(0,Z.jsx)("span",{style:{fontSize:"1.5rem",alignSelf:"flex-end",margin:"0rem 0.5rem 0.15rem 0.15rem"},children:"ATALYST"})]},"navout-6")]},"navout-4")},"navout-3")},"navout-2")},"navout-1")}}}]);
//# sourceMappingURL=38.ec189c44.chunk.js.map