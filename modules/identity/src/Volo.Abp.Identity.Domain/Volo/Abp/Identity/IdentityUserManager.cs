using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using JetBrains.Annotations;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Volo.Abp.Domain.Entities;
using Volo.Abp.Domain.Services;
using Volo.Abp.Threading;

namespace Volo.Abp.Identity
{
    public class IdentityUserManager : UserManager<IdentityUser>, IDomainService
    {
        protected override CancellationToken CancellationToken => _cancellationTokenProvider.Token;

        private readonly ICancellationTokenProvider _cancellationTokenProvider;
        
        private readonly IIdentityUserRepository _userRepository;

        public IdentityUserManager(
            IdentityUserStore store,
            IOptions<IdentityOptions> optionsAccessor,
            IPasswordHasher<IdentityUser> passwordHasher,
            IEnumerable<IUserValidator<IdentityUser>> userValidators,
            IEnumerable<IPasswordValidator<IdentityUser>> passwordValidators,
            ILookupNormalizer keyNormalizer,
            IdentityErrorDescriber errors,
            IServiceProvider services,
            ILogger<IdentityUserManager> logger,
            ICancellationTokenProvider cancellationTokenProvider,
            IIdentityUserRepository userRepository)
            : base(
                  store,
                  optionsAccessor,
                  passwordHasher,
                  userValidators,
                  passwordValidators,
                  keyNormalizer,
                  errors,
                  services,
                  logger)
        {
            _cancellationTokenProvider = cancellationTokenProvider;
            _userRepository = userRepository;
        }

        public virtual async Task<IdentityUser> GetByIdAsync(Guid id)
        {
            var user = await Store.FindByIdAsync(id.ToString(), CancellationToken);
            if (user == null)
            {
                throw new EntityNotFoundException(typeof(IdentityUser), id);
            }

            return user;
        }

        public virtual async Task<IdentityResult> SetRolesAsync([NotNull] IdentityUser user, [NotNull] IEnumerable<string> roleNames)
        {
            Check.NotNull(user, nameof(user));
            Check.NotNull(roleNames, nameof(roleNames));

            var currentRoleNames = await GetRolesAsync(user);

            var result = await RemoveFromRolesAsync(user, currentRoleNames.Except(roleNames).Distinct());
            if (!result.Succeeded)
            {
                return result;
            }

            result = await AddToRolesAsync(user, roleNames.Except(currentRoleNames).Distinct());
            if (!result.Succeeded)
            {
                return result;
            }

            return IdentityResult.Success;
        }
        
        public virtual async Task<IdentityUser> FindByPhoneNumberAsync(string phoneNumber)
        {
            return await _userRepository.FindByPhoneNumberAsync(phoneNumber);
        }

        public virtual async Task<List<IdentityUser>> GetListAsync()
        {
            return await _userRepository.GetListAsync();
        }

        public virtual async Task<List<IdentityRole>> GetRolesAsync(Guid id)
        {
            return await _userRepository.GetRolesAsync(id);
        }
