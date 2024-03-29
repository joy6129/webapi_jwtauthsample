﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace webapi_jwtauthsample.Controllers
{
    [Authorize(Roles="Admin")]    
    [Route("api/[controller]")]
    [ApiController]    
    public class ValuesController : ControllerBase
    {
        // GET api/values
        [HttpGet]
        [AllowAnonymous]   // means every one can access, the user can access this action without authorize
        public ActionResult<IEnumerable<string>> Get()
        {         
            return new string[] { "value1", "value2" };
        }

        // GET api/values/5
        [HttpGet("{id}")]        
        public ActionResult<string> Get(int id)
        {
            var email = User.Claims.Where(C => C.Type == ClaimTypes.Email).Select(c => c.Value).SingleOrDefault();
            if (email != "joy6129@gmail.com")
                return "You are not Joy";
            else
                return "value";
        }

        // POST api/values
        [HttpPost]
        public void Post([FromBody] string value)
        {
        }

        // PUT api/values/5
        [HttpPut("{id}")]
        public void Put(int id, [FromBody] string value)
        {
        }

        // DELETE api/values/5
        [HttpDelete("{id}")]
        public void Delete(int id)
        {
        }
    }
}
