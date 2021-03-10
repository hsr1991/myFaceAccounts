using Microsoft.AspNetCore.Mvc;
using MyFace.Models.Request;
using MyFace.Models.Response;
using MyFace.Repositories;
using System;
using System.Text;
using Microsoft.AspNetCore.Cryptography.KeyDerivation;
using System.Web;


namespace MyFace.Controllers
{
    [ApiController]
    [Route("/posts")]
    public class PostsController : ControllerBase
    {
        private readonly IPostsRepo _posts;
        private readonly IUsersRepo _users;



        public PostsController(IPostsRepo posts, IUsersRepo users)
        {
            _posts = posts;
            _users = users;
        }


        [HttpGet("")]
        public ActionResult<PostListResponse> Search([FromQuery] PostSearchRequest searchRequest)
        {
            var posts = _posts.Search(searchRequest);
            var postCount = _posts.Count(searchRequest);
            return PostListResponse.Create(searchRequest, posts, postCount);
        }

        [HttpGet("{id}")]
        public ActionResult<PostResponse> GetById([FromRoute] int id)
        {
            var post = _posts.GetById(id);
            return new PostResponse(post);
        }


        [HttpPost("create")]
        public IActionResult Create([FromBody] CreatePostRequest newPost)
        {
            string authorizationHeader = Request.Headers["Authorization"];

            if (authorizationHeader != null && authorizationHeader.StartsWith("Basic"))
            {
                string encodedUsernamePassword = authorizationHeader.Substring("Basic ".Length).Trim();
                Encoding encoding = Encoding.GetEncoding("iso-8859-1");
                string usernamePassword = encoding.GetString(Convert.FromBase64String(encodedUsernamePassword));

                int seperatorIndex = usernamePassword.IndexOf(':');

                string username = usernamePassword.Substring(0, seperatorIndex);
                string password = usernamePassword.Substring(seperatorIndex + 1);

                var user = _users.GetByUsername(username);

                var userSaltString = user.Salt;

                byte[] userSalt = Encoding.ASCII.GetBytes(userSaltString);

                string hashed = Convert.ToBase64String(KeyDerivation.Pbkdf2(
                password: password,
                salt: userSalt,
                prf: KeyDerivationPrf.HMACSHA1,
                iterationCount: 10000,
                numBytesRequested: 256 / 8));

                if (hashed == user.HashedPassword && ModelState.IsValid)
                {
                    var post = _posts.Create(newPost);

                    var url = Url.Action("GetById", new { id = post.Id });
                    var postResponse = new PostResponse(post);
                    return Created(url, postResponse);
                }
                else if (!ModelState.IsValid)
                {
                    return BadRequest(ModelState);
                }
                else
                {
                    return Unauthorized();
                };

            }
            else
            {
                throw new Exception("The authorization header is either empty or isn't Basic.");
            }

        }

        [HttpPatch("{id}/update")]
        public ActionResult<PostResponse> Update([FromRoute] int id, [FromBody] UpdatePostRequest update)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            var post = _posts.Update(id, update);
            return new PostResponse(post);
        }

        [HttpDelete("{id}")]
        public IActionResult Delete([FromRoute] int id)
        {
            _posts.Delete(id);
            return Ok();
        }
    }
}